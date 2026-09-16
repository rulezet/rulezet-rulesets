rule TTP_XOR_MULT_DOSStub_9cf9 {
  strings:
    $key_9cf9 = { c8 91 [2] bc 89 [2] fb 8b [2] bc 9a [2] f2 96 [2] fe 9c [2] e9 97 [2] f2 d9 [2] cf }

  condition:
    any of them
}