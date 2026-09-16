rule TTP_XOR_MULT_DOSStub_9c72 {
  strings:
    $key_9c72 = { c8 1a [2] bc 02 [2] fb 00 [2] bc 11 [2] f2 1d [2] fe 17 [2] e9 1c [2] f2 52 [2] cf }

  condition:
    any of them
}