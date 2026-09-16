rule TTP_XOR_MULT_DOSStub_339e {
  strings:
    $key_339e = { 67 f6 [2] 13 ee [2] 54 ec [2] 13 fd [2] 5d f1 [2] 51 fb [2] 46 f0 [2] 5d be [2] 60 }

  condition:
    any of them
}