rule TTP_XOR_MULT_DOSStub_798b {
  strings:
    $key_798b = { 2d e3 [2] 59 fb [2] 1e f9 [2] 59 e8 [2] 17 e4 [2] 1b ee [2] 0c e5 [2] 17 ab [2] 2a }

  condition:
    any of them
}