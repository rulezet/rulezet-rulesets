rule TTP_XOR_MULT_DOSStub_9c4c {
  strings:
    $key_9c4c = { c8 24 [2] bc 3c [2] fb 3e [2] bc 2f [2] f2 23 [2] fe 29 [2] e9 22 [2] f2 6c [2] cf }

  condition:
    any of them
}