rule TTP_XOR_MULT_DOSStub_e8a0 {
  strings:
    $key_e8a0 = { bc c8 [2] c8 d0 [2] 8f d2 [2] c8 c3 [2] 86 cf [2] 8a c5 [2] 9d ce [2] 86 80 [2] bb }

  condition:
    any of them
}