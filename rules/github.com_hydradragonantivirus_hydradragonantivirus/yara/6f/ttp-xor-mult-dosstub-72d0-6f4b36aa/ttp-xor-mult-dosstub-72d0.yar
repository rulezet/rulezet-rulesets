rule TTP_XOR_MULT_DOSStub_72d0 {
  strings:
    $key_72d0 = { 26 b8 [2] 52 a0 [2] 15 a2 [2] 52 b3 [2] 1c bf [2] 10 b5 [2] 07 be [2] 1c f0 [2] 21 }

  condition:
    any of them
}