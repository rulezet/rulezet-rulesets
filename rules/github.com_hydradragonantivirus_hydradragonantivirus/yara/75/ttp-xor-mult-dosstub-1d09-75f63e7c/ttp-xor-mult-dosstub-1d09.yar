rule TTP_XOR_MULT_DOSStub_1d09 {
  strings:
    $key_1d09 = { 49 61 [2] 3d 79 [2] 7a 7b [2] 3d 6a [2] 73 66 [2] 7f 6c [2] 68 67 [2] 73 29 [2] 4e }

  condition:
    any of them
}