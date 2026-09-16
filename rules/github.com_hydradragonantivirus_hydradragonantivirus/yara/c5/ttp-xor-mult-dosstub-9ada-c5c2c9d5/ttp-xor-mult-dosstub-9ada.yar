rule TTP_XOR_MULT_DOSStub_9ada {
  strings:
    $key_9ada = { ce b2 [2] ba aa [2] fd a8 [2] ba b9 [2] f4 b5 [2] f8 bf [2] ef b4 [2] f4 fa [2] c9 }

  condition:
    any of them
}