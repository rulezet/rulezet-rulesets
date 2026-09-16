rule TTP_XOR_MULT_DOSStub_ac50 {
  strings:
    $key_ac50 = { f8 38 [2] 8c 20 [2] cb 22 [2] 8c 33 [2] c2 3f [2] ce 35 [2] d9 3e [2] c2 70 [2] ff }

  condition:
    any of them
}