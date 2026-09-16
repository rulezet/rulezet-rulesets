rule TTP_XOR_MULT_DOSStub_9a93 {
  strings:
    $key_9a93 = { ce fb [2] ba e3 [2] fd e1 [2] ba f0 [2] f4 fc [2] f8 f6 [2] ef fd [2] f4 b3 [2] c9 }

  condition:
    any of them
}