rule TTP_XOR_MULT_DOSStub_01c8 {
  strings:
    $key_01c8 = { 55 a0 [2] 21 b8 [2] 66 ba [2] 21 ab [2] 6f a7 [2] 63 ad [2] 74 a6 [2] 6f e8 [2] 52 }

  condition:
    any of them
}