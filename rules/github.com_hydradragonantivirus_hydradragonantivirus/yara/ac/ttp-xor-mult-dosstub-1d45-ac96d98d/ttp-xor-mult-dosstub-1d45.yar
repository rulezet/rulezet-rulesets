rule TTP_XOR_MULT_DOSStub_1d45 {
  strings:
    $key_1d45 = { 49 2d [2] 3d 35 [2] 7a 37 [2] 3d 26 [2] 73 2a [2] 7f 20 [2] 68 2b [2] 73 65 [2] 4e }

  condition:
    any of them
}