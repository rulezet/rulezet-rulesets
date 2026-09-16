rule TTP_XOR_MULT_DOSStub_9a83 {
  strings:
    $key_9a83 = { ce eb [2] ba f3 [2] fd f1 [2] ba e0 [2] f4 ec [2] f8 e6 [2] ef ed [2] f4 a3 [2] c9 }

  condition:
    any of them
}