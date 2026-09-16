rule TTP_XOR_MULT_DOSStub_9c7f {
  strings:
    $key_9c7f = { c8 17 [2] bc 0f [2] fb 0d [2] bc 1c [2] f2 10 [2] fe 1a [2] e9 11 [2] f2 5f [2] cf }

  condition:
    any of them
}