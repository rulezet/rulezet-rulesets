rule TTP_XOR_MULT_DOSStub_9c41 {
  strings:
    $key_9c41 = { c8 29 [2] bc 31 [2] fb 33 [2] bc 22 [2] f2 2e [2] fe 24 [2] e9 2f [2] f2 61 [2] cf }

  condition:
    any of them
}