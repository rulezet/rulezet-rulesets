rule TTP_XOR_MULT_DOSStub_0ac8 {
  strings:
    $key_0ac8 = { 5e a0 [2] 2a b8 [2] 6d ba [2] 2a ab [2] 64 a7 [2] 68 ad [2] 7f a6 [2] 64 e8 [2] 59 }

  condition:
    any of them
}