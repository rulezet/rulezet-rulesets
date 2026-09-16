rule TTP_XOR_MULT_DOSStub_9c30 {
  strings:
    $key_9c30 = { c8 58 [2] bc 40 [2] fb 42 [2] bc 53 [2] f2 5f [2] fe 55 [2] e9 5e [2] f2 10 [2] cf }

  condition:
    any of them
}