rule TTP_XOR_MULT_DOSStub_acf6 {
  strings:
    $key_acf6 = { f8 9e [2] 8c 86 [2] cb 84 [2] 8c 95 [2] c2 99 [2] ce 93 [2] d9 98 [2] c2 d6 [2] ff }

  condition:
    any of them
}