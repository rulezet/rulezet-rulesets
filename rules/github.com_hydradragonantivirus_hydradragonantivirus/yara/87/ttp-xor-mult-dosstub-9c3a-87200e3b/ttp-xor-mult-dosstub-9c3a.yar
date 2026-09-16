rule TTP_XOR_MULT_DOSStub_9c3a {
  strings:
    $key_9c3a = { c8 52 [2] bc 4a [2] fb 48 [2] bc 59 [2] f2 55 [2] fe 5f [2] e9 54 [2] f2 1a [2] cf }

  condition:
    any of them
}