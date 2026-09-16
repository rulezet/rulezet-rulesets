rule TTP_XOR_MULT_DOSStub_2ac8 {
  strings:
    $key_2ac8 = { 7e a0 [2] 0a b8 [2] 4d ba [2] 0a ab [2] 44 a7 [2] 48 ad [2] 5f a6 [2] 44 e8 [2] 79 }

  condition:
    any of them
}