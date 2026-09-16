rule TTP_XOR_MULT_DOSStub_9ad0 {
  strings:
    $key_9ad0 = { ce b8 [2] ba a0 [2] fd a2 [2] ba b3 [2] f4 bf [2] f8 b5 [2] ef be [2] f4 f0 [2] c9 }

  condition:
    any of them
}