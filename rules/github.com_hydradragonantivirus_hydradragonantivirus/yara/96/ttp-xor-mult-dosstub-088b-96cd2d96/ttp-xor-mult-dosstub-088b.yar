rule TTP_XOR_MULT_DOSStub_088b {
  strings:
    $key_088b = { 5c e3 [2] 28 fb [2] 6f f9 [2] 28 e8 [2] 66 e4 [2] 6a ee [2] 7d e5 [2] 66 ab [2] 5b }

  condition:
    any of them
}