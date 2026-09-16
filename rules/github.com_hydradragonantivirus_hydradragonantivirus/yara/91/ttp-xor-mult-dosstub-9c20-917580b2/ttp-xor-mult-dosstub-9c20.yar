rule TTP_XOR_MULT_DOSStub_9c20 {
  strings:
    $key_9c20 = { c8 48 [2] bc 50 [2] fb 52 [2] bc 43 [2] f2 4f [2] fe 45 [2] e9 4e [2] f2 00 [2] cf }

  condition:
    any of them
}