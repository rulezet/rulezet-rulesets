rule TTP_XOR_MULT_DOSStub_4847 {
  strings:
    $key_4847 = { 1c 2f [2] 68 37 [2] 2f 35 [2] 68 24 [2] 26 28 [2] 2a 22 [2] 3d 29 [2] 26 67 [2] 1b }

  condition:
    any of them
}