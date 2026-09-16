rule TTP_XOR_MULT_DOSStub_1d69 {
  strings:
    $key_1d69 = { 49 01 [2] 3d 19 [2] 7a 1b [2] 3d 0a [2] 73 06 [2] 7f 0c [2] 68 07 [2] 73 49 [2] 4e }

  condition:
    any of them
}