rule TTP_XOR_MULT_DOSStub_9c0a {
  strings:
    $key_9c0a = { c8 62 [2] bc 7a [2] fb 78 [2] bc 69 [2] f2 65 [2] fe 6f [2] e9 64 [2] f2 2a [2] cf }

  condition:
    any of them
}