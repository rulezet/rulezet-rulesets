rule TTP_XOR_MULT_DOSStub_ac8b {
  strings:
    $key_ac8b = { f8 e3 [2] 8c fb [2] cb f9 [2] 8c e8 [2] c2 e4 [2] ce ee [2] d9 e5 [2] c2 ab [2] ff }

  condition:
    any of them
}