rule TTP_XOR_MULT_DOSStub_9c62 {
  strings:
    $key_9c62 = { c8 0a [2] bc 12 [2] fb 10 [2] bc 01 [2] f2 0d [2] fe 07 [2] e9 0c [2] f2 42 [2] cf }

  condition:
    any of them
}