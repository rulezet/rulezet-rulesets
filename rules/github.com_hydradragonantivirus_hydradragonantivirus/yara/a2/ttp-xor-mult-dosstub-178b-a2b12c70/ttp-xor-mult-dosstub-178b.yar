rule TTP_XOR_MULT_DOSStub_178b {
  strings:
    $key_178b = { 43 e3 [2] 37 fb [2] 70 f9 [2] 37 e8 [2] 79 e4 [2] 75 ee [2] 62 e5 [2] 79 ab [2] 44 }

  condition:
    any of them
}