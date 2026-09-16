rule TTP_XOR_MULT_DOSStub_9c78 {
  strings:
    $key_9c78 = { c8 10 [2] bc 08 [2] fb 0a [2] bc 1b [2] f2 17 [2] fe 1d [2] e9 16 [2] f2 58 [2] cf }

  condition:
    any of them
}