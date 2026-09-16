rule TTP_XOR_MULT_DOSStub_acc9 {
  strings:
    $key_acc9 = { f8 a1 [2] 8c b9 [2] cb bb [2] 8c aa [2] c2 a6 [2] ce ac [2] d9 a7 [2] c2 e9 [2] ff }

  condition:
    any of them
}