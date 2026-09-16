rule TTP_XOR_MULT_DOSStub_9ce8 {
  strings:
    $key_9ce8 = { c8 80 [2] bc 98 [2] fb 9a [2] bc 8b [2] f2 87 [2] fe 8d [2] e9 86 [2] f2 c8 [2] cf }

  condition:
    any of them
}