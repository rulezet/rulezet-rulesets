rule TTP_XOR_MULT_DOSStub_9c36 {
  strings:
    $key_9c36 = { c8 5e [2] bc 46 [2] fb 44 [2] bc 55 [2] f2 59 [2] fe 53 [2] e9 58 [2] f2 16 [2] cf }

  condition:
    any of them
}