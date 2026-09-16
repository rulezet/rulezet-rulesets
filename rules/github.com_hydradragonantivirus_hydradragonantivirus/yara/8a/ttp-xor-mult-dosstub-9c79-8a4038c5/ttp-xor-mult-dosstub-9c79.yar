rule TTP_XOR_MULT_DOSStub_9c79 {
  strings:
    $key_9c79 = { c8 11 [2] bc 09 [2] fb 0b [2] bc 1a [2] f2 16 [2] fe 1c [2] e9 17 [2] f2 59 [2] cf }

  condition:
    any of them
}