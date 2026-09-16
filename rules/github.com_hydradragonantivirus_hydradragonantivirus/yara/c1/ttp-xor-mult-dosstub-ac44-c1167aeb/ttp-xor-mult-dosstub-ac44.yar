rule TTP_XOR_MULT_DOSStub_ac44 {
  strings:
    $key_ac44 = { f8 2c [2] 8c 34 [2] cb 36 [2] 8c 27 [2] c2 2b [2] ce 21 [2] d9 2a [2] c2 64 [2] ff }

  condition:
    any of them
}