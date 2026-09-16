rule TTP_XOR_MULT_DOSStub_abda {
  strings:
    $key_abda = { ff b2 [2] 8b aa [2] cc a8 [2] 8b b9 [2] c5 b5 [2] c9 bf [2] de b4 [2] c5 fa [2] f8 }

  condition:
    any of them
}