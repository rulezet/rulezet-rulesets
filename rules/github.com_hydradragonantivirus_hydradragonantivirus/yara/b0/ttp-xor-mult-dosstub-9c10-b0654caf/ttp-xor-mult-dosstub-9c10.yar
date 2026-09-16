rule TTP_XOR_MULT_DOSStub_9c10 {
  strings:
    $key_9c10 = { c8 78 [2] bc 60 [2] fb 62 [2] bc 73 [2] f2 7f [2] fe 75 [2] e9 7e [2] f2 30 [2] cf }

  condition:
    any of them
}