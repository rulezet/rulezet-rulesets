rule TTP_XOR_MULT_DOSStub_acc1 {
  strings:
    $key_acc1 = { f8 a9 [2] 8c b1 [2] cb b3 [2] 8c a2 [2] c2 ae [2] ce a4 [2] d9 af [2] c2 e1 [2] ff }

  condition:
    any of them
}