rule TTP_XOR_MULT_DOSStub_9c75 {
  strings:
    $key_9c75 = { c8 1d [2] bc 05 [2] fb 07 [2] bc 16 [2] f2 1a [2] fe 10 [2] e9 1b [2] f2 55 [2] cf }

  condition:
    any of them
}