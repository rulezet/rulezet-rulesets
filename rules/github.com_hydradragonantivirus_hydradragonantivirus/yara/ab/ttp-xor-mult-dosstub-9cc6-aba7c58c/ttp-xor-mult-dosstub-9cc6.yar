rule TTP_XOR_MULT_DOSStub_9cc6 {
  strings:
    $key_9cc6 = { c8 ae [2] bc b6 [2] fb b4 [2] bc a5 [2] f2 a9 [2] fe a3 [2] e9 a8 [2] f2 e6 [2] cf }

  condition:
    any of them
}