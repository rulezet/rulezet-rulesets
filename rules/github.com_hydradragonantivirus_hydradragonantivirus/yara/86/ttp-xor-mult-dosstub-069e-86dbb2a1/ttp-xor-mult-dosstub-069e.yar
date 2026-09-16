rule TTP_XOR_MULT_DOSStub_069e {
  strings:
    $key_069e = { 52 f6 [2] 26 ee [2] 61 ec [2] 26 fd [2] 68 f1 [2] 64 fb [2] 73 f0 [2] 68 be [2] 55 }

  condition:
    any of them
}