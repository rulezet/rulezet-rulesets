rule TTP_XOR_MULT_DOSStub_4baa {
  strings:
    $key_4baa = { 1f c2 [2] 6b da [2] 2c d8 [2] 6b c9 [2] 25 c5 [2] 29 cf [2] 3e c4 [2] 25 8a [2] 18 }

  condition:
    any of them
}