rule TTP_XOR_MULT_DOSStub_9cf1 {
  strings:
    $key_9cf1 = { c8 99 [2] bc 81 [2] fb 83 [2] bc 92 [2] f2 9e [2] fe 94 [2] e9 9f [2] f2 d1 [2] cf }

  condition:
    any of them
}