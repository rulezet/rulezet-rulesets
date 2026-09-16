rule TTP_XOR_MULT_DOSStub_9c22 {
  strings:
    $key_9c22 = { c8 4a [2] bc 52 [2] fb 50 [2] bc 41 [2] f2 4d [2] fe 47 [2] e9 4c [2] f2 02 [2] cf }

  condition:
    any of them
}