rule TTP_XOR_MULT_DOSStub_9c37 {
  strings:
    $key_9c37 = { c8 5f [2] bc 47 [2] fb 45 [2] bc 54 [2] f2 58 [2] fe 52 [2] e9 59 [2] f2 17 [2] cf }

  condition:
    any of them
}