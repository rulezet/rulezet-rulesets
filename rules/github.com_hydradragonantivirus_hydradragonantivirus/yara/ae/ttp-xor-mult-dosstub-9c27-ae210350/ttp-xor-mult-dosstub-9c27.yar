rule TTP_XOR_MULT_DOSStub_9c27 {
  strings:
    $key_9c27 = { c8 4f [2] bc 57 [2] fb 55 [2] bc 44 [2] f2 48 [2] fe 42 [2] e9 49 [2] f2 07 [2] cf }

  condition:
    any of them
}