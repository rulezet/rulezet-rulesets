rule TTP_XOR_MULT_DOSStub_acc7 {
  strings:
    $key_acc7 = { f8 af [2] 8c b7 [2] cb b5 [2] 8c a4 [2] c2 a8 [2] ce a2 [2] d9 a9 [2] c2 e7 [2] ff }

  condition:
    any of them
}