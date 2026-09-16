rule TTP_XOR_MULT_DOSStub_7ac8 {
  strings:
    $key_7ac8 = { 2e a0 [2] 5a b8 [2] 1d ba [2] 5a ab [2] 14 a7 [2] 18 ad [2] 0f a6 [2] 14 e8 [2] 29 }

  condition:
    any of them
}