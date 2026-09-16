rule TTP_XOR_MULT_DOSStub_9cb9 {
  strings:
    $key_9cb9 = { c8 d1 [2] bc c9 [2] fb cb [2] bc da [2] f2 d6 [2] fe dc [2] e9 d7 [2] f2 99 [2] cf }

  condition:
    any of them
}