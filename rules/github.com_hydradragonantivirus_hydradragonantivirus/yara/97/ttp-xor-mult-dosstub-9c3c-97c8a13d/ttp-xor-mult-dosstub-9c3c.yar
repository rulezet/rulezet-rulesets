rule TTP_XOR_MULT_DOSStub_9c3c {
  strings:
    $key_9c3c = { c8 54 [2] bc 4c [2] fb 4e [2] bc 5f [2] f2 53 [2] fe 59 [2] e9 52 [2] f2 1c [2] cf }

  condition:
    any of them
}