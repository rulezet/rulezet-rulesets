rule TTP_XOR_MULT_DOSStub_af95 {
  strings:
    $key_af95 = { fb fd [2] 8f e5 [2] c8 e7 [2] 8f f6 [2] c1 fa [2] cd f0 [2] da fb [2] c1 b5 [2] fc }

  condition:
    any of them
}