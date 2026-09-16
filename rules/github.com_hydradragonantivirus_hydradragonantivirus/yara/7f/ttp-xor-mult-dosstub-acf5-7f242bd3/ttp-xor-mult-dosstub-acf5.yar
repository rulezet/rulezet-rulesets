rule TTP_XOR_MULT_DOSStub_acf5 {
  strings:
    $key_acf5 = { f8 9d [2] 8c 85 [2] cb 87 [2] 8c 96 [2] c2 9a [2] ce 90 [2] d9 9b [2] c2 d5 [2] ff }

  condition:
    any of them
}