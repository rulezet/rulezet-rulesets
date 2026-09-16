rule TTP_XOR_MULT_DOSStub_9c4a {
  strings:
    $key_9c4a = { c8 22 [2] bc 3a [2] fb 38 [2] bc 29 [2] f2 25 [2] fe 2f [2] e9 24 [2] f2 6a [2] cf }

  condition:
    any of them
}