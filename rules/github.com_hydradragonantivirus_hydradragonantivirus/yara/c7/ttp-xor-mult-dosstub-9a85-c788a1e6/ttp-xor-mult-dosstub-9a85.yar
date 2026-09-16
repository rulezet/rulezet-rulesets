rule TTP_XOR_MULT_DOSStub_9a85 {
  strings:
    $key_9a85 = { ce ed [2] ba f5 [2] fd f7 [2] ba e6 [2] f4 ea [2] f8 e0 [2] ef eb [2] f4 a5 [2] c9 }

  condition:
    any of them
}