rule TTP_XOR_MULT_DOSStub_9a92 {
  strings:
    $key_9a92 = { ce fa [2] ba e2 [2] fd e0 [2] ba f1 [2] f4 fd [2] f8 f7 [2] ef fc [2] f4 b2 [2] c9 }

  condition:
    any of them
}