rule TTP_XOR_MULT_DOSStub_9c17 {
  strings:
    $key_9c17 = { c8 7f [2] bc 67 [2] fb 65 [2] bc 74 [2] f2 78 [2] fe 72 [2] e9 79 [2] f2 37 [2] cf }

  condition:
    any of them
}