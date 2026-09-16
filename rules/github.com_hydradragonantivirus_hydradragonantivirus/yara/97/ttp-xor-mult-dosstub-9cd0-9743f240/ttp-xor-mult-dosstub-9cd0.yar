rule TTP_XOR_MULT_DOSStub_9cd0 {
  strings:
    $key_9cd0 = { c8 b8 [2] bc a0 [2] fb a2 [2] bc b3 [2] f2 bf [2] fe b5 [2] e9 be [2] f2 f0 [2] cf }

  condition:
    any of them
}