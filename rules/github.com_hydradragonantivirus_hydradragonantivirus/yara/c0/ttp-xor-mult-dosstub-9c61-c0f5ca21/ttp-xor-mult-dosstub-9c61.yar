rule TTP_XOR_MULT_DOSStub_9c61 {
  strings:
    $key_9c61 = { c8 09 [2] bc 11 [2] fb 13 [2] bc 02 [2] f2 0e [2] fe 04 [2] e9 0f [2] f2 41 [2] cf }

  condition:
    any of them
}