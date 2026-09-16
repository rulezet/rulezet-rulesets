rule TTP_XOR_MULT_DOSStub_9c66 {
  strings:
    $key_9c66 = { c8 0e [2] bc 16 [2] fb 14 [2] bc 05 [2] f2 09 [2] fe 03 [2] e9 08 [2] f2 46 [2] cf }

  condition:
    any of them
}