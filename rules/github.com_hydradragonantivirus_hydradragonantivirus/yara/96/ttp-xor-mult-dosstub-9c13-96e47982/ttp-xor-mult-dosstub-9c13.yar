rule TTP_XOR_MULT_DOSStub_9c13 {
  strings:
    $key_9c13 = { c8 7b [2] bc 63 [2] fb 61 [2] bc 70 [2] f2 7c [2] fe 76 [2] e9 7d [2] f2 33 [2] cf }

  condition:
    any of them
}