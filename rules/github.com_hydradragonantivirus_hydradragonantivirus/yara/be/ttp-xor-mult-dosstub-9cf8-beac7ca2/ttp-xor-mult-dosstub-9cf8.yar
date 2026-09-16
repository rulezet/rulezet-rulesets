rule TTP_XOR_MULT_DOSStub_9cf8 {
  strings:
    $key_9cf8 = { c8 90 [2] bc 88 [2] fb 8a [2] bc 9b [2] f2 97 [2] fe 9d [2] e9 96 [2] f2 d8 [2] cf }

  condition:
    any of them
}