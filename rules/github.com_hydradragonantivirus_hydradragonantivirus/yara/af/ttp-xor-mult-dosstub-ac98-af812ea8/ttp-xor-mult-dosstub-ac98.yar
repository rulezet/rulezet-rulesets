rule TTP_XOR_MULT_DOSStub_ac98 {
  strings:
    $key_ac98 = { f8 f0 [2] 8c e8 [2] cb ea [2] 8c fb [2] c2 f7 [2] ce fd [2] d9 f6 [2] c2 b8 [2] ff }

  condition:
    any of them
}