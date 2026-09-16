rule TTP_XOR_MULT_DOSStub_9ad1 {
  strings:
    $key_9ad1 = { ce b9 [2] ba a1 [2] fd a3 [2] ba b2 [2] f4 be [2] f8 b4 [2] ef bf [2] f4 f1 [2] c9 }

  condition:
    any of them
}