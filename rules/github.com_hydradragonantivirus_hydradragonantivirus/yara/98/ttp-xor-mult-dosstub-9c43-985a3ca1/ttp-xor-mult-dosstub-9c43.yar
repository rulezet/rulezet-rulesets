rule TTP_XOR_MULT_DOSStub_9c43 {
  strings:
    $key_9c43 = { c8 2b [2] bc 33 [2] fb 31 [2] bc 20 [2] f2 2c [2] fe 26 [2] e9 2d [2] f2 63 [2] cf }

  condition:
    any of them
}