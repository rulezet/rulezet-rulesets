rule TTP_XOR_MULT_DOSStub_9a94 {
  strings:
    $key_9a94 = { ce fc [2] ba e4 [2] fd e6 [2] ba f7 [2] f4 fb [2] f8 f1 [2] ef fa [2] f4 b4 [2] c9 }

  condition:
    any of them
}