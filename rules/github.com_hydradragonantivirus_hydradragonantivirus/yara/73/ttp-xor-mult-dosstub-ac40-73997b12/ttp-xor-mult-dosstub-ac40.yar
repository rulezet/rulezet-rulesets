rule TTP_XOR_MULT_DOSStub_ac40 {
  strings:
    $key_ac40 = { f8 28 [2] 8c 30 [2] cb 32 [2] 8c 23 [2] c2 2f [2] ce 25 [2] d9 2e [2] c2 60 [2] ff }

  condition:
    any of them
}