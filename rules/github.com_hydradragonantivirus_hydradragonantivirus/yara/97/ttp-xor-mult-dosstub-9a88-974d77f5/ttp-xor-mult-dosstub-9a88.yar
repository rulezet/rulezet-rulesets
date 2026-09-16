rule TTP_XOR_MULT_DOSStub_9a88 {
  strings:
    $key_9a88 = { ce e0 [2] ba f8 [2] fd fa [2] ba eb [2] f4 e7 [2] f8 ed [2] ef e6 [2] f4 a8 [2] c9 }

  condition:
    any of them
}