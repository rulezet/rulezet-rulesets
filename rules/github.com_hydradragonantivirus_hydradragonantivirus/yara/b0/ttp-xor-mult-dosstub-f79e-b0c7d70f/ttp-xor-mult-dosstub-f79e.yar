rule TTP_XOR_MULT_DOSStub_f79e {
  strings:
    $key_f79e = { a3 f6 [2] d7 ee [2] 90 ec [2] d7 fd [2] 99 f1 [2] 95 fb [2] 82 f0 [2] 99 be [2] a4 }

  condition:
    any of them
}