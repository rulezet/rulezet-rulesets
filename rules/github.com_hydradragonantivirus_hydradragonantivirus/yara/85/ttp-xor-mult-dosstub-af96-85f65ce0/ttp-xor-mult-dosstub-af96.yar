rule TTP_XOR_MULT_DOSStub_af96 {
  strings:
    $key_af96 = { fb fe [2] 8f e6 [2] c8 e4 [2] 8f f5 [2] c1 f9 [2] cd f3 [2] da f8 [2] c1 b6 [2] fc }

  condition:
    any of them
}