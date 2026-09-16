rule TTP_XOR_MULT_DOSStub_ebce {
  strings:
    $key_ebce = { bf a6 [2] cb be [2] 8c bc [2] cb ad [2] 85 a1 [2] 89 ab [2] 9e a0 [2] 85 ee [2] b8 }

  condition:
    any of them
}