rule TTP_XOR_MULT_DOSStub_9cd9 {
  strings:
    $key_9cd9 = { c8 b1 [2] bc a9 [2] fb ab [2] bc ba [2] f2 b6 [2] fe bc [2] e9 b7 [2] f2 f9 [2] cf }

  condition:
    any of them
}