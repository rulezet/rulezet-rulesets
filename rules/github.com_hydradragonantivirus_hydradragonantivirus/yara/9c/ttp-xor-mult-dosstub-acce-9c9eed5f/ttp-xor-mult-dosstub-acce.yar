rule TTP_XOR_MULT_DOSStub_acce {
  strings:
    $key_acce = { f8 a6 [2] 8c be [2] cb bc [2] 8c ad [2] c2 a1 [2] ce ab [2] d9 a0 [2] c2 ee [2] ff }

  condition:
    any of them
}