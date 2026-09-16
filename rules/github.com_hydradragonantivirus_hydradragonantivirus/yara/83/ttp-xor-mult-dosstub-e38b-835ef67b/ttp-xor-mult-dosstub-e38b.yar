rule TTP_XOR_MULT_DOSStub_e38b {
  strings:
    $key_e38b = { b7 e3 [2] c3 fb [2] 84 f9 [2] c3 e8 [2] 8d e4 [2] 81 ee [2] 96 e5 [2] 8d ab [2] b0 }

  condition:
    any of them
}