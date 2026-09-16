rule TTP_XOR_MULT_DOSStub_9ce6 {
  strings:
    $key_9ce6 = { c8 8e [2] bc 96 [2] fb 94 [2] bc 85 [2] f2 89 [2] fe 83 [2] e9 88 [2] f2 c6 [2] cf }

  condition:
    any of them
}