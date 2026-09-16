rule TTP_XOR_MULT_DOSStub_3ac8 {
  strings:
    $key_3ac8 = { 6e a0 [2] 1a b8 [2] 5d ba [2] 1a ab [2] 54 a7 [2] 58 ad [2] 4f a6 [2] 54 e8 [2] 69 }

  condition:
    any of them
}