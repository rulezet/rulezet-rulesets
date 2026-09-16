rule TTP_XOR_MULT_DOSStub_ac7d {
  strings:
    $key_ac7d = { f8 15 [2] 8c 0d [2] cb 0f [2] 8c 1e [2] c2 12 [2] ce 18 [2] d9 13 [2] c2 5d [2] ff }

  condition:
    any of them
}