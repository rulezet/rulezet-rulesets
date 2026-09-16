rule TTP_XOR_MULT_DOSStub_5ac8 {
  strings:
    $key_5ac8 = { 0e a0 [2] 7a b8 [2] 3d ba [2] 7a ab [2] 34 a7 [2] 38 ad [2] 2f a6 [2] 34 e8 [2] 09 }

  condition:
    any of them
}