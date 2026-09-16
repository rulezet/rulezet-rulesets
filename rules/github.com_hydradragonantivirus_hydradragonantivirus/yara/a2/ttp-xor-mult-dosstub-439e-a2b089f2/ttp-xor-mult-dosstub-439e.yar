rule TTP_XOR_MULT_DOSStub_439e {
  strings:
    $key_439e = { 17 f6 [2] 63 ee [2] 24 ec [2] 63 fd [2] 2d f1 [2] 21 fb [2] 36 f0 [2] 2d be [2] 10 }

  condition:
    any of them
}