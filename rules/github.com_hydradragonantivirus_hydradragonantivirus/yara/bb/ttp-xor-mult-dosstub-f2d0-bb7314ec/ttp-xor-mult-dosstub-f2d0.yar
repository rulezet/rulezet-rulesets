rule TTP_XOR_MULT_DOSStub_f2d0 {
  strings:
    $key_f2d0 = { a6 b8 [2] d2 a0 [2] 95 a2 [2] d2 b3 [2] 9c bf [2] 90 b5 [2] 87 be [2] 9c f0 [2] a1 }

  condition:
    any of them
}