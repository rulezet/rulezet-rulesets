rule TTP_XOR_MULT_DOSStub_49aa {
  strings:
    $key_49aa = { 1d c2 [2] 69 da [2] 2e d8 [2] 69 c9 [2] 27 c5 [2] 2b cf [2] 3c c4 [2] 27 8a [2] 1a }

  condition:
    any of them
}