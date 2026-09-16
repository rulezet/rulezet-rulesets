rule TTP_XOR_MULT_DOSStub_b2b9 {
  strings:
    $key_b2b9 = { e6 d1 [2] 92 c9 [2] d5 cb [2] 92 da [2] dc d6 [2] d0 dc [2] c7 d7 [2] dc 99 [2] e1 }

  condition:
    any of them
}