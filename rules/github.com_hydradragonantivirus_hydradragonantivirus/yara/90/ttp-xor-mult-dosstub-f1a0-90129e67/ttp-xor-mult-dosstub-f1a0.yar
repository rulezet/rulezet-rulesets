rule TTP_XOR_MULT_DOSStub_f1a0 {
  strings:
    $key_f1a0 = { a5 c8 [2] d1 d0 [2] 96 d2 [2] d1 c3 [2] 9f cf [2] 93 c5 [2] 84 ce [2] 9f 80 [2] a2 }

  condition:
    any of them
}