rule TTP_XOR_MULT_DOSStub_9c73 {
  strings:
    $key_9c73 = { c8 1b [2] bc 03 [2] fb 01 [2] bc 10 [2] f2 1c [2] fe 16 [2] e9 1d [2] f2 53 [2] cf }

  condition:
    any of them
}