rule TTP_XOR_MULT_DOSStub_9c60 {
  strings:
    $key_9c60 = { c8 08 [2] bc 10 [2] fb 12 [2] bc 03 [2] f2 0f [2] fe 05 [2] e9 0e [2] f2 40 [2] cf }

  condition:
    any of them
}