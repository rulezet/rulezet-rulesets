rule TTP_XOR_MULT_DOSStub_b5a7 {
  strings:
    $key_b5a7 = { e1 cf [2] 95 d7 [2] d2 d5 [2] 95 c4 [2] db c8 [2] d7 c2 [2] c0 c9 [2] db 87 [2] e6 }

  condition:
    any of them
}