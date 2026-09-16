rule TTP_XOR_MULT_DOSStub_9c1b {
  strings:
    $key_9c1b = { c8 73 [2] bc 6b [2] fb 69 [2] bc 78 [2] f2 74 [2] fe 7e [2] e9 75 [2] f2 3b [2] cf }

  condition:
    any of them
}