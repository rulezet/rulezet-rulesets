rule TTP_XOR_MULT_DOSStub_9cda {
  strings:
    $key_9cda = { c8 b2 [2] bc aa [2] fb a8 [2] bc b9 [2] f2 b5 [2] fe bf [2] e9 b4 [2] f2 fa [2] cf }

  condition:
    any of them
}