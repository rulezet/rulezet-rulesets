rule TTP_XOR_MULT_DOSStub_e0a0 {
  strings:
    $key_e0a0 = { b4 c8 [2] c0 d0 [2] 87 d2 [2] c0 c3 [2] 8e cf [2] 82 c5 [2] 95 ce [2] 8e 80 [2] b3 }

  condition:
    any of them
}