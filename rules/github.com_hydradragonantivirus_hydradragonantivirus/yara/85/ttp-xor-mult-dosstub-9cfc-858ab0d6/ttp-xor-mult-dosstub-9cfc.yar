rule TTP_XOR_MULT_DOSStub_9cfc {
  strings:
    $key_9cfc = { c8 94 [2] bc 8c [2] fb 8e [2] bc 9f [2] f2 93 [2] fe 99 [2] e9 92 [2] f2 dc [2] cf }

  condition:
    any of them
}