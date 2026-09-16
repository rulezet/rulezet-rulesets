rule TTP_XOR_MULT_DOSStub_afc3 {
  strings:
    $key_afc3 = { fb ab [2] 8f b3 [2] c8 b1 [2] 8f a0 [2] c1 ac [2] cd a6 [2] da ad [2] c1 e3 [2] fc }

  condition:
    any of them
}