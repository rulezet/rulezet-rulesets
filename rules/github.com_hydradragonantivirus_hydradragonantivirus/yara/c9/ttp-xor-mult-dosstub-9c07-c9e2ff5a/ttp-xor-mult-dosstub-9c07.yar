rule TTP_XOR_MULT_DOSStub_9c07 {
  strings:
    $key_9c07 = { c8 6f [2] bc 77 [2] fb 75 [2] bc 64 [2] f2 68 [2] fe 62 [2] e9 69 [2] f2 27 [2] cf }

  condition:
    any of them
}