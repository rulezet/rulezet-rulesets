rule TTP_XOR_MULT_DOSStub_9ce2 {
  strings:
    $key_9ce2 = { c8 8a [2] bc 92 [2] fb 90 [2] bc 81 [2] f2 8d [2] fe 87 [2] e9 8c [2] f2 c2 [2] cf }

  condition:
    any of them
}