rule TTP_XOR_MULT_DOSStub_9cd6 {
  strings:
    $key_9cd6 = { c8 be [2] bc a6 [2] fb a4 [2] bc b5 [2] f2 b9 [2] fe b3 [2] e9 b8 [2] f2 f6 [2] cf }

  condition:
    any of them
}