rule TTP_XOR_MULT_DOSStub_9c77 {
  strings:
    $key_9c77 = { c8 1f [2] bc 07 [2] fb 05 [2] bc 14 [2] f2 18 [2] fe 12 [2] e9 19 [2] f2 57 [2] cf }

  condition:
    any of them
}