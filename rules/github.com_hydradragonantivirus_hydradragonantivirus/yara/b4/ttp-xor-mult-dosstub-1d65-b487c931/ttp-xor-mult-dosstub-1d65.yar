rule TTP_XOR_MULT_DOSStub_1d65 {
  strings:
    $key_1d65 = { 49 0d [2] 3d 15 [2] 7a 17 [2] 3d 06 [2] 73 0a [2] 7f 00 [2] 68 0b [2] 73 45 [2] 4e }

  condition:
    any of them
}