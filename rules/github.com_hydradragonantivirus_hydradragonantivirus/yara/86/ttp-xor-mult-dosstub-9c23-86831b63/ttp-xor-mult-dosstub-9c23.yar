rule TTP_XOR_MULT_DOSStub_9c23 {
  strings:
    $key_9c23 = { c8 4b [2] bc 53 [2] fb 51 [2] bc 40 [2] f2 4c [2] fe 46 [2] e9 4d [2] f2 03 [2] cf }

  condition:
    any of them
}