rule TTP_XOR_MULT_DOSStub_9c25 {
  strings:
    $key_9c25 = { c8 4d [2] bc 55 [2] fb 57 [2] bc 46 [2] f2 4a [2] fe 40 [2] e9 4b [2] f2 05 [2] cf }

  condition:
    any of them
}