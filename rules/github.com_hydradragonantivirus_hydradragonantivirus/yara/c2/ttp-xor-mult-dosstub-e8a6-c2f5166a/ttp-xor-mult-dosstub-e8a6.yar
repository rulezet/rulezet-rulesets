rule TTP_XOR_MULT_DOSStub_e8a6 {
  strings:
    $key_e8a6 = { bc ce [2] c8 d6 [2] 8f d4 [2] c8 c5 [2] 86 c9 [2] 8a c3 [2] 9d c8 [2] 86 86 [2] bb }

  condition:
    any of them
}