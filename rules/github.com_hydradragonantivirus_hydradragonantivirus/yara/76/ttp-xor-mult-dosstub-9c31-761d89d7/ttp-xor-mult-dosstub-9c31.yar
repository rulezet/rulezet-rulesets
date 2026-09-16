rule TTP_XOR_MULT_DOSStub_9c31 {
  strings:
    $key_9c31 = { c8 59 [2] bc 41 [2] fb 43 [2] bc 52 [2] f2 5e [2] fe 54 [2] e9 5f [2] f2 11 [2] cf }

  condition:
    any of them
}