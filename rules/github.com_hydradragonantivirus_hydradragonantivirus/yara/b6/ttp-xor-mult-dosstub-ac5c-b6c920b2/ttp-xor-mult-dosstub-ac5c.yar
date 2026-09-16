rule TTP_XOR_MULT_DOSStub_ac5c {
  strings:
    $key_ac5c = { f8 34 [2] 8c 2c [2] cb 2e [2] 8c 3f [2] c2 33 [2] ce 39 [2] d9 32 [2] c2 7c [2] ff }

  condition:
    any of them
}