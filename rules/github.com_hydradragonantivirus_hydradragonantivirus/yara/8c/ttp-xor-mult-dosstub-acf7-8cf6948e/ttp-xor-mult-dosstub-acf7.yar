rule TTP_XOR_MULT_DOSStub_acf7 {
  strings:
    $key_acf7 = { f8 9f [2] 8c 87 [2] cb 85 [2] 8c 94 [2] c2 98 [2] ce 92 [2] d9 99 [2] c2 d7 [2] ff }

  condition:
    any of them
}