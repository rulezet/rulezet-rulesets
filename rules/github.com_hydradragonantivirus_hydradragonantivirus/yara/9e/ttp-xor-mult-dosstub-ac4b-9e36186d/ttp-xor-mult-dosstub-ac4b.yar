rule TTP_XOR_MULT_DOSStub_ac4b {
  strings:
    $key_ac4b = { f8 23 [2] 8c 3b [2] cb 39 [2] 8c 28 [2] c2 24 [2] ce 2e [2] d9 25 [2] c2 6b [2] ff }

  condition:
    any of them
}