rule TTP_XOR_MULT_DOSStub_1d25 {
  strings:
    $key_1d25 = { 49 4d [2] 3d 55 [2] 7a 57 [2] 3d 46 [2] 73 4a [2] 7f 40 [2] 68 4b [2] 73 05 [2] 4e }

  condition:
    any of them
}