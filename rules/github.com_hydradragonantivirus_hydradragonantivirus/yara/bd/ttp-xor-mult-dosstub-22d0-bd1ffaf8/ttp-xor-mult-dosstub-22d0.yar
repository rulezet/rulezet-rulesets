rule TTP_XOR_MULT_DOSStub_22d0 {
  strings:
    $key_22d0 = { 76 b8 [2] 02 a0 [2] 45 a2 [2] 02 b3 [2] 4c bf [2] 40 b5 [2] 57 be [2] 4c f0 [2] 71 }

  condition:
    any of them
}