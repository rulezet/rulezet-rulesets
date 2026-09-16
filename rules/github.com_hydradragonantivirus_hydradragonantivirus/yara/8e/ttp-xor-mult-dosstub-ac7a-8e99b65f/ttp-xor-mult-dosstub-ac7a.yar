rule TTP_XOR_MULT_DOSStub_ac7a {
  strings:
    $key_ac7a = { f8 12 [2] 8c 0a [2] cb 08 [2] 8c 19 [2] c2 15 [2] ce 1f [2] d9 14 [2] c2 5a [2] ff }

  condition:
    any of them
}