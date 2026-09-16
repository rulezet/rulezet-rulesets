rule TTP_XOR_MULT_DOSStub_ac2a {
  strings:
    $key_ac2a = { f8 42 [2] 8c 5a [2] cb 58 [2] 8c 49 [2] c2 45 [2] ce 4f [2] d9 44 [2] c2 0a [2] ff }

  condition:
    any of them
}