rule TTP_XOR_MULT_DOSStub_ac47 {
  strings:
    $key_ac47 = { f8 2f [2] 8c 37 [2] cb 35 [2] 8c 24 [2] c2 28 [2] ce 22 [2] d9 29 [2] c2 67 [2] ff }

  condition:
    any of them
}