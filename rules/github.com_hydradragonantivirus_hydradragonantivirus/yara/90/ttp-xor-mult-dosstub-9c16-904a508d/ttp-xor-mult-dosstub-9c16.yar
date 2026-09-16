rule TTP_XOR_MULT_DOSStub_9c16 {
  strings:
    $key_9c16 = { c8 7e [2] bc 66 [2] fb 64 [2] bc 75 [2] f2 79 [2] fe 73 [2] e9 78 [2] f2 36 [2] cf }

  condition:
    any of them
}