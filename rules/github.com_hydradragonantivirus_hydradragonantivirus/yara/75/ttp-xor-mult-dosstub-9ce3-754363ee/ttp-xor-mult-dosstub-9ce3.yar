rule TTP_XOR_MULT_DOSStub_9ce3 {
  strings:
    $key_9ce3 = { c8 8b [2] bc 93 [2] fb 91 [2] bc 80 [2] f2 8c [2] fe 86 [2] e9 8d [2] f2 c3 [2] cf }

  condition:
    any of them
}