rule TTP_XOR_MULT_DOSStub_9c47 {
  strings:
    $key_9c47 = { c8 2f [2] bc 37 [2] fb 35 [2] bc 24 [2] f2 28 [2] fe 22 [2] e9 29 [2] f2 67 [2] cf }

  condition:
    any of them
}