rule TTP_XOR_MULT_DOSStub_ac71 {
  strings:
    $key_ac71 = { f8 19 [2] 8c 01 [2] cb 03 [2] 8c 12 [2] c2 1e [2] ce 14 [2] d9 1f [2] c2 51 [2] ff }

  condition:
    any of them
}