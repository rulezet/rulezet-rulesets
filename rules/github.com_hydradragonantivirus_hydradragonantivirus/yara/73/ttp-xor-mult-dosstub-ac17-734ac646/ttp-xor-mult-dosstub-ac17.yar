rule TTP_XOR_MULT_DOSStub_ac17 {
  strings:
    $key_ac17 = { f8 7f [2] 8c 67 [2] cb 65 [2] 8c 74 [2] c2 78 [2] ce 72 [2] d9 79 [2] c2 37 [2] ff }

  condition:
    any of them
}