rule TTP_XOR_MULT_DOSStub_9c42 {
  strings:
    $key_9c42 = { c8 2a [2] bc 32 [2] fb 30 [2] bc 21 [2] f2 2d [2] fe 27 [2] e9 2c [2] f2 62 [2] cf }

  condition:
    any of them
}