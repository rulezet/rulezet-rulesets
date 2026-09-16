rule TTP_XOR_MULT_DOSStub_ac10 {
  strings:
    $key_ac10 = { f8 78 [2] 8c 60 [2] cb 62 [2] 8c 73 [2] c2 7f [2] ce 75 [2] d9 7e [2] c2 30 [2] ff }

  condition:
    any of them
}