rule TTP_XOR_MULT_DOSStub_9ce0 {
  strings:
    $key_9ce0 = { c8 88 [2] bc 90 [2] fb 92 [2] bc 83 [2] f2 8f [2] fe 85 [2] e9 8e [2] f2 c0 [2] cf }

  condition:
    any of them
}