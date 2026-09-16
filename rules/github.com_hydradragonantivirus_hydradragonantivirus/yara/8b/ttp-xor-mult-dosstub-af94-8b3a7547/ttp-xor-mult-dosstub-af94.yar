rule TTP_XOR_MULT_DOSStub_af94 {
  strings:
    $key_af94 = { fb fc [2] 8f e4 [2] c8 e6 [2] 8f f7 [2] c1 fb [2] cd f1 [2] da fa [2] c1 b4 [2] fc }

  condition:
    any of them
}