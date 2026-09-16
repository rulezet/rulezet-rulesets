rule TTP_XOR_MULT_DOSStub_9c76 {
  strings:
    $key_9c76 = { c8 1e [2] bc 06 [2] fb 04 [2] bc 15 [2] f2 19 [2] fe 13 [2] e9 18 [2] f2 56 [2] cf }

  condition:
    any of them
}