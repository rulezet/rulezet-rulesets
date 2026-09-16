rule TTP_XOR_MULT_DOSStub_ac1a {
  strings:
    $key_ac1a = { f8 72 [2] 8c 6a [2] cb 68 [2] 8c 79 [2] c2 75 [2] ce 7f [2] d9 74 [2] c2 3a [2] ff }

  condition:
    any of them
}