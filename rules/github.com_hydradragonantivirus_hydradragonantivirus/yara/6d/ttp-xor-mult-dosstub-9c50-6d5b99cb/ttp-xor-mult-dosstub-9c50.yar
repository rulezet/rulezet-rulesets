rule TTP_XOR_MULT_DOSStub_9c50 {
  strings:
    $key_9c50 = { c8 38 [2] bc 20 [2] fb 22 [2] bc 33 [2] f2 3f [2] fe 35 [2] e9 3e [2] f2 70 [2] cf }

  condition:
    any of them
}