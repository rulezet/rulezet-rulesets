rule TTP_XOR_MULT_DOSStub_9c3f {
  strings:
    $key_9c3f = { c8 57 [2] bc 4f [2] fb 4d [2] bc 5c [2] f2 50 [2] fe 5a [2] e9 51 [2] f2 1f [2] cf }

  condition:
    any of them
}