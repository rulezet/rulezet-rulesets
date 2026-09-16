rule TTP_XOR_MULT_DOSStub_738b {
  strings:
    $key_738b = { 27 e3 [2] 53 fb [2] 14 f9 [2] 53 e8 [2] 1d e4 [2] 11 ee [2] 06 e5 [2] 1d ab [2] 20 }

  condition:
    any of them
}