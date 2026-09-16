rule TTP_XOR_MULT_DOSStub_9ce9 {
  strings:
    $key_9ce9 = { c8 81 [2] bc 99 [2] fb 9b [2] bc 8a [2] f2 86 [2] fe 8c [2] e9 87 [2] f2 c9 [2] cf }

  condition:
    any of them
}