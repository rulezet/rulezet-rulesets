rule TTP_XOR_MULT_DOSStub_9caa {
  strings:
    $key_9caa = { c8 c2 [2] bc da [2] fb d8 [2] bc c9 [2] f2 c5 [2] fe cf [2] e9 c4 [2] f2 8a [2] cf }

  condition:
    any of them
}