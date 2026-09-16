rule TTP_XOR_MULT_DOSStub_acc3 {
  strings:
    $key_acc3 = { f8 ab [2] 8c b3 [2] cb b1 [2] 8c a0 [2] c2 ac [2] ce a6 [2] d9 ad [2] c2 e3 [2] ff }

  condition:
    any of them
}