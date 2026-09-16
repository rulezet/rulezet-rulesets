rule TTP_XOR_MULT_DOSStub_9c56 {
  strings:
    $key_9c56 = { c8 3e [2] bc 26 [2] fb 24 [2] bc 35 [2] f2 39 [2] fe 33 [2] e9 38 [2] f2 76 [2] cf }

  condition:
    any of them
}