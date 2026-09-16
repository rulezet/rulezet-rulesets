rule TTP_XOR_MULT_DOSStub_5898 {
  strings:
    $key_5898 = { 0c f0 [2] 78 e8 [2] 3f ea [2] 78 fb [2] 36 f7 [2] 3a fd [2] 2d f6 [2] 36 b8 [2] 0b }

  condition:
    any of them
}