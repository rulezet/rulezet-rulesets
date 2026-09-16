rule TTP_XOR_MULT_DOSStub_9c74 {
  strings:
    $key_9c74 = { c8 1c [2] bc 04 [2] fb 06 [2] bc 17 [2] f2 1b [2] fe 11 [2] e9 1a [2] f2 54 [2] cf }

  condition:
    any of them
}