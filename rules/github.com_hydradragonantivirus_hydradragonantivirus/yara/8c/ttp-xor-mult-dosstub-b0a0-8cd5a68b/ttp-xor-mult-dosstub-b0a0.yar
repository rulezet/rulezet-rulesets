rule TTP_XOR_MULT_DOSStub_b0a0 {
  strings:
    $key_b0a0 = { e4 c8 [2] 90 d0 [2] d7 d2 [2] 90 c3 [2] de cf [2] d2 c5 [2] c5 ce [2] de 80 [2] e3 }

  condition:
    any of them
}