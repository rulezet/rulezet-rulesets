rule TTP_XOR_MULT_DOSStub_9cb1 {
  strings:
    $key_9cb1 = { c8 d9 [2] bc c1 [2] fb c3 [2] bc d2 [2] f2 de [2] fe d4 [2] e9 df [2] f2 91 [2] cf }

  condition:
    any of them
}