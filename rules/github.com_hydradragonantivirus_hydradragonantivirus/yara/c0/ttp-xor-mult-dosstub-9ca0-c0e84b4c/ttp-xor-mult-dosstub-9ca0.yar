rule TTP_XOR_MULT_DOSStub_9ca0 {
  strings:
    $key_9ca0 = { c8 c8 [2] bc d0 [2] fb d2 [2] bc c3 [2] f2 cf [2] fe c5 [2] e9 ce [2] f2 80 [2] cf }

  condition:
    any of them
}