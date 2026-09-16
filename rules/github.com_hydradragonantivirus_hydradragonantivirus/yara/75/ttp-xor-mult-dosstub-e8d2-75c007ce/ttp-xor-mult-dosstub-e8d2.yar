rule TTP_XOR_MULT_DOSStub_e8d2 {
  strings:
    $key_e8d2 = { bc ba [2] c8 a2 [2] 8f a0 [2] c8 b1 [2] 86 bd [2] 8a b7 [2] 9d bc [2] 86 f2 [2] bb }

  condition:
    any of them
}