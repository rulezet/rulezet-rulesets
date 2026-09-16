rule TTP_XOR_MULT_DOSStub_acd9 {
  strings:
    $key_acd9 = { f8 b1 [2] 8c a9 [2] cb ab [2] 8c ba [2] c2 b6 [2] ce bc [2] d9 b7 [2] c2 f9 [2] ff }

  condition:
    any of them
}