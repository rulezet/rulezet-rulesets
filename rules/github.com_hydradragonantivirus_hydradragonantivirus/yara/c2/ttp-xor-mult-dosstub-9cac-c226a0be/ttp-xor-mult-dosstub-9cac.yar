rule TTP_XOR_MULT_DOSStub_9cac {
  strings:
    $key_9cac = { c8 c4 [2] bc dc [2] fb de [2] bc cf [2] f2 c3 [2] fe c9 [2] e9 c2 [2] f2 8c [2] cf }

  condition:
    any of them
}