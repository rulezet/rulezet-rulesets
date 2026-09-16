rule TTP_XOR_MULT_DOSStub_9cee {
  strings:
    $key_9cee = { c8 86 [2] bc 9e [2] fb 9c [2] bc 8d [2] f2 81 [2] fe 8b [2] e9 80 [2] f2 ce [2] cf }

  condition:
    any of them
}