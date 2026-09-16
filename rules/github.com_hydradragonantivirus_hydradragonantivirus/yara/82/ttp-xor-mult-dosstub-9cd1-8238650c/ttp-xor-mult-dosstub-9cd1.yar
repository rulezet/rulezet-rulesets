rule TTP_XOR_MULT_DOSStub_9cd1 {
  strings:
    $key_9cd1 = { c8 b9 [2] bc a1 [2] fb a3 [2] bc b2 [2] f2 be [2] fe b4 [2] e9 bf [2] f2 f1 [2] cf }

  condition:
    any of them
}