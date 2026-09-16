rule TTP_XOR_MULT_DOSStub_9cbc {
  strings:
    $key_9cbc = { c8 d4 [2] bc cc [2] fb ce [2] bc df [2] f2 d3 [2] fe d9 [2] e9 d2 [2] f2 9c [2] cf }

  condition:
    any of them
}