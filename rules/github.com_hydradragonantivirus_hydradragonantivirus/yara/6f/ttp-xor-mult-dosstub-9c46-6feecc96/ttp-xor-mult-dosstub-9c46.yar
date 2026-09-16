rule TTP_XOR_MULT_DOSStub_9c46 {
  strings:
    $key_9c46 = { c8 2e [2] bc 36 [2] fb 34 [2] bc 25 [2] f2 29 [2] fe 23 [2] e9 28 [2] f2 66 [2] cf }

  condition:
    any of them
}