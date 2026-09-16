rule TTP_XOR_MULT_DOSStub_9cc7 {
  strings:
    $key_9cc7 = { c8 af [2] bc b7 [2] fb b5 [2] bc a4 [2] f2 a8 [2] fe a2 [2] e9 a9 [2] f2 e7 [2] cf }

  condition:
    any of them
}