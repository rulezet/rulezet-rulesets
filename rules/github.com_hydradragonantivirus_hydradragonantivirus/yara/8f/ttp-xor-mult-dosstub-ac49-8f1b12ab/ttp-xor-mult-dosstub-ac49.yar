rule TTP_XOR_MULT_DOSStub_ac49 {
  strings:
    $key_ac49 = { f8 21 [2] 8c 39 [2] cb 3b [2] 8c 2a [2] c2 26 [2] ce 2c [2] d9 27 [2] c2 69 [2] ff }

  condition:
    any of them
}