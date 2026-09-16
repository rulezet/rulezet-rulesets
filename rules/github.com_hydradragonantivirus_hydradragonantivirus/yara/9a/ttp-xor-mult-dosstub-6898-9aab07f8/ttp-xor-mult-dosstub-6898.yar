rule TTP_XOR_MULT_DOSStub_6898 {
  strings:
    $key_6898 = { 3c f0 [2] 48 e8 [2] 0f ea [2] 48 fb [2] 06 f7 [2] 0a fd [2] 1d f6 [2] 06 b8 [2] 3b }

  condition:
    any of them
}