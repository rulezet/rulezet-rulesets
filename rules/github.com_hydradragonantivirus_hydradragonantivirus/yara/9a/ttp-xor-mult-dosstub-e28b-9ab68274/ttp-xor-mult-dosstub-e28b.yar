rule TTP_XOR_MULT_DOSStub_e28b {
  strings:
    $key_e28b = { b6 e3 [2] c2 fb [2] 85 f9 [2] c2 e8 [2] 8c e4 [2] 80 ee [2] 97 e5 [2] 8c ab [2] b1 }

  condition:
    any of them
}