rule TTP_XOR_MULT_DOSStub_9c01 {
  strings:
    $key_9c01 = { c8 69 [2] bc 71 [2] fb 73 [2] bc 62 [2] f2 6e [2] fe 64 [2] e9 6f [2] f2 21 [2] cf }

  condition:
    any of them
}