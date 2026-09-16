rule TTP_XOR_MULT_DOSStub_9cd5 {
  strings:
    $key_9cd5 = { c8 bd [2] bc a5 [2] fb a7 [2] bc b6 [2] f2 ba [2] fe b0 [2] e9 bb [2] f2 f5 [2] cf }

  condition:
    any of them
}