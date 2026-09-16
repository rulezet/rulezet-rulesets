rule TTP_XOR_MULT_DOSStub_b59e {
  strings:
    $key_b59e = { e1 f6 [2] 95 ee [2] d2 ec [2] 95 fd [2] db f1 [2] d7 fb [2] c0 f0 [2] db be [2] e6 }

  condition:
    any of them
}