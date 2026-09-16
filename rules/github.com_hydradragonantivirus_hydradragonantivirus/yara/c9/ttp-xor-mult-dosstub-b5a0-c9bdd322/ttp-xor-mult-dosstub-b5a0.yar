rule TTP_XOR_MULT_DOSStub_b5a0 {
  strings:
    $key_b5a0 = { e1 c8 [2] 95 d0 [2] d2 d2 [2] 95 c3 [2] db cf [2] d7 c5 [2] c0 ce [2] db 80 [2] e6 }

  condition:
    any of them
}