rule TTP_XOR_MULT_DOSStub_9ce7 {
  strings:
    $key_9ce7 = { c8 8f [2] bc 97 [2] fb 95 [2] bc 84 [2] f2 88 [2] fe 82 [2] e9 89 [2] f2 c7 [2] cf }

  condition:
    any of them
}