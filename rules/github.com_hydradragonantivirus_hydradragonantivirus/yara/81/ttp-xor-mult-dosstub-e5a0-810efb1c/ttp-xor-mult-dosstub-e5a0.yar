rule TTP_XOR_MULT_DOSStub_e5a0 {
  strings:
    $key_e5a0 = { b1 c8 [2] c5 d0 [2] 82 d2 [2] c5 c3 [2] 8b cf [2] 87 c5 [2] 90 ce [2] 8b 80 [2] b6 }

  condition:
    any of them
}