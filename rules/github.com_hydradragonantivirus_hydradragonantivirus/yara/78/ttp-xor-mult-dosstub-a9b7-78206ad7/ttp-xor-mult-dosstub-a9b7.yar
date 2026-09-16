rule TTP_XOR_MULT_DOSStub_a9b7 {
  strings:
    $key_a9b7 = { fd df [2] 89 c7 [2] ce c5 [2] 89 d4 [2] c7 d8 [2] cb d2 [2] dc d9 [2] c7 97 [2] fa }

  condition:
    any of them
}