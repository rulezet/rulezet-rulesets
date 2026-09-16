rule TTP_XOR_MULT_DOSStub_4ac8 {
  strings:
    $key_4ac8 = { 1e a0 [2] 6a b8 [2] 2d ba [2] 6a ab [2] 24 a7 [2] 28 ad [2] 3f a6 [2] 24 e8 [2] 19 }

  condition:
    any of them
}