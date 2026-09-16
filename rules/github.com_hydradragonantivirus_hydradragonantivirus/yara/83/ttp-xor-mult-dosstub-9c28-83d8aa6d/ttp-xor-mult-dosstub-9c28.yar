rule TTP_XOR_MULT_DOSStub_9c28 {
  strings:
    $key_9c28 = { c8 40 [2] bc 58 [2] fb 5a [2] bc 4b [2] f2 47 [2] fe 4d [2] e9 46 [2] f2 08 [2] cf }

  condition:
    any of them
}