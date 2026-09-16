rule TTP_XOR_MULT_DOSStub_9c63 {
  strings:
    $key_9c63 = { c8 0b [2] bc 13 [2] fb 11 [2] bc 00 [2] f2 0c [2] fe 06 [2] e9 0d [2] f2 43 [2] cf }

  condition:
    any of them
}