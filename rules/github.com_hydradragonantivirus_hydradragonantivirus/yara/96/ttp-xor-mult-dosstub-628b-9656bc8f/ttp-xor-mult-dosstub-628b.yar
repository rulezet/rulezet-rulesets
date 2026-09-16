rule TTP_XOR_MULT_DOSStub_628b {
  strings:
    $key_628b = { 36 e3 [2] 42 fb [2] 05 f9 [2] 42 e8 [2] 0c e4 [2] 00 ee [2] 17 e5 [2] 0c ab [2] 31 }

  condition:
    any of them
}