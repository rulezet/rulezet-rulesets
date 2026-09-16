rule TTP_XOR_MULT_DOSStub_138b {
  strings:
    $key_138b = { 47 e3 [2] 33 fb [2] 74 f9 [2] 33 e8 [2] 7d e4 [2] 71 ee [2] 66 e5 [2] 7d ab [2] 40 }

  condition:
    any of them
}