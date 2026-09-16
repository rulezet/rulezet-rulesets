rule TTP_XOR_MULT_DOSStub_acad {
  strings:
    $key_acad = { f8 c5 [2] 8c dd [2] cb df [2] 8c ce [2] c2 c2 [2] ce c8 [2] d9 c3 [2] c2 8d [2] ff }

  condition:
    any of them
}