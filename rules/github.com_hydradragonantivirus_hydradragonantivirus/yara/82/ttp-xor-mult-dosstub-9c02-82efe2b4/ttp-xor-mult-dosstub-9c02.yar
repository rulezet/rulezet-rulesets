rule TTP_XOR_MULT_DOSStub_9c02 {
  strings:
    $key_9c02 = { c8 6a [2] bc 72 [2] fb 70 [2] bc 61 [2] f2 6d [2] fe 67 [2] e9 6c [2] f2 22 [2] cf }

  condition:
    any of them
}