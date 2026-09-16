rule TTP_XOR_MULT_DOSStub_acc8 {
  strings:
    $key_acc8 = { f8 a0 [2] 8c b8 [2] cb ba [2] 8c ab [2] c2 a7 [2] ce ad [2] d9 a6 [2] c2 e8 [2] ff }

  condition:
    any of them
}