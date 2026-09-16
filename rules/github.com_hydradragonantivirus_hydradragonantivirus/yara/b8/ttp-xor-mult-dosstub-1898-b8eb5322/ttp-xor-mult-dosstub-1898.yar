rule TTP_XOR_MULT_DOSStub_1898 {
  strings:
    $key_1898 = { 4c f0 [2] 38 e8 [2] 7f ea [2] 38 fb [2] 76 f7 [2] 7a fd [2] 6d f6 [2] 76 b8 [2] 4b }

  condition:
    any of them
}