rule TTP_XOR_MULT_DOSStub_ebda {
  strings:
    $key_ebda = { bf b2 [2] cb aa [2] 8c a8 [2] cb b9 [2] 85 b5 [2] 89 bf [2] 9e b4 [2] 85 fa [2] b8 }

  condition:
    any of them
}