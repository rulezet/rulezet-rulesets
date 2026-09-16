rule TTP_XOR_MULT_DOSStub_298b {
  strings:
    $key_298b = { 7d e3 [2] 09 fb [2] 4e f9 [2] 09 e8 [2] 47 e4 [2] 4b ee [2] 5c e5 [2] 47 ab [2] 7a }

  condition:
    any of them
}