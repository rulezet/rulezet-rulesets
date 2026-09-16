rule TTP_XOR_MULT_DOSStub_9cd2 {
  strings:
    $key_9cd2 = { c8 ba [2] bc a2 [2] fb a0 [2] bc b1 [2] f2 bd [2] fe b7 [2] e9 bc [2] f2 f2 [2] cf }

  condition:
    any of them
}