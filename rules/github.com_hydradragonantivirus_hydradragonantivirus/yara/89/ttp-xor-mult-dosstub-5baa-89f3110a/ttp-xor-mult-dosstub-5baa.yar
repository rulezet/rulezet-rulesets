rule TTP_XOR_MULT_DOSStub_5baa {
  strings:
    $key_5baa = { 0f c2 [2] 7b da [2] 3c d8 [2] 7b c9 [2] 35 c5 [2] 39 cf [2] 2e c4 [2] 35 8a [2] 08 }

  condition:
    any of them
}