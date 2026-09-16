rule TTP_XOR_MULT_DOSStub_9c7e {
  strings:
    $key_9c7e = { c8 16 [2] bc 0e [2] fb 0c [2] bc 1d [2] f2 11 [2] fe 1b [2] e9 10 [2] f2 5e [2] cf }

  condition:
    any of them
}