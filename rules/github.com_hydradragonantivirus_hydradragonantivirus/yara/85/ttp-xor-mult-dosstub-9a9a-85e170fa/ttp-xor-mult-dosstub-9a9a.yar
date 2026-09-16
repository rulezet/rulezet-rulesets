rule TTP_XOR_MULT_DOSStub_9a9a {
  strings:
    $key_9a9a = { ce f2 [2] ba ea [2] fd e8 [2] ba f9 [2] f4 f5 [2] f8 ff [2] ef f4 [2] f4 ba [2] c9 }

  condition:
    any of them
}