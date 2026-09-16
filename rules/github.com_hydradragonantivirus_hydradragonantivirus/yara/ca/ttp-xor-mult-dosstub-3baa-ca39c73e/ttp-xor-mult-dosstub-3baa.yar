rule TTP_XOR_MULT_DOSStub_3baa {
  strings:
    $key_3baa = { 6f c2 [2] 1b da [2] 5c d8 [2] 1b c9 [2] 55 c5 [2] 59 cf [2] 4e c4 [2] 55 8a [2] 68 }

  condition:
    any of them
}