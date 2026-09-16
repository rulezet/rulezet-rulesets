rule TTP_XOR_MULT_DOSStub_9c35 {
  strings:
    $key_9c35 = { c8 5d [2] bc 45 [2] fb 47 [2] bc 56 [2] f2 5a [2] fe 50 [2] e9 5b [2] f2 15 [2] cf }

  condition:
    any of them
}