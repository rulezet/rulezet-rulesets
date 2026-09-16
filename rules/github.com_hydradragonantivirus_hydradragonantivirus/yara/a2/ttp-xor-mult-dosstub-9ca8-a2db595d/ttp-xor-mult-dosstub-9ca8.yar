rule TTP_XOR_MULT_DOSStub_9ca8 {
  strings:
    $key_9ca8 = { c8 c0 [2] bc d8 [2] fb da [2] bc cb [2] f2 c7 [2] fe cd [2] e9 c6 [2] f2 88 [2] cf }

  condition:
    any of them
}