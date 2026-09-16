rule TTP_XOR_MULT_DOSStub_9c65 {
  strings:
    $key_9c65 = { c8 0d [2] bc 15 [2] fb 17 [2] bc 06 [2] f2 0a [2] fe 00 [2] e9 0b [2] f2 45 [2] cf }

  condition:
    any of them
}