rule TTP_XOR_MULT_DOSStub_128b {
  strings:
    $key_128b = { 46 e3 [2] 32 fb [2] 75 f9 [2] 32 e8 [2] 7c e4 [2] 70 ee [2] 67 e5 [2] 7c ab [2] 41 }

  condition:
    any of them
}