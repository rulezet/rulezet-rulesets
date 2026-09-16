rule TTP_XOR_MULT_DOSStub_9c52 {
  strings:
    $key_9c52 = { c8 3a [2] bc 22 [2] fb 20 [2] bc 31 [2] f2 3d [2] fe 37 [2] e9 3c [2] f2 72 [2] cf }

  condition:
    any of them
}