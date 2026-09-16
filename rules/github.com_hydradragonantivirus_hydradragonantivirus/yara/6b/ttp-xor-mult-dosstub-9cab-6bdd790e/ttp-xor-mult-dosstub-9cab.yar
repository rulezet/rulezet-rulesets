rule TTP_XOR_MULT_DOSStub_9cab {
  strings:
    $key_9cab = { c8 c3 [2] bc db [2] fb d9 [2] bc c8 [2] f2 c4 [2] fe ce [2] e9 c5 [2] f2 8b [2] cf }

  condition:
    any of them
}