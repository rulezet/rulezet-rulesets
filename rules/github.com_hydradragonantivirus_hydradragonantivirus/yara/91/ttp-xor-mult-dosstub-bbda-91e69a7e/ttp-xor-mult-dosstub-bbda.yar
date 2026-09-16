rule TTP_XOR_MULT_DOSStub_bbda {
  strings:
    $key_bbda = { ef b2 [2] 9b aa [2] dc a8 [2] 9b b9 [2] d5 b5 [2] d9 bf [2] ce b4 [2] d5 fa [2] e8 }

  condition:
    any of them
}