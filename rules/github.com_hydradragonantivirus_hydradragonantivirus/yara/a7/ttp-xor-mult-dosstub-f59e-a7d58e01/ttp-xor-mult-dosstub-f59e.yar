rule TTP_XOR_MULT_DOSStub_f59e {
  strings:
    $key_f59e = { a1 f6 [2] d5 ee [2] 92 ec [2] d5 fd [2] 9b f1 [2] 97 fb [2] 80 f0 [2] 9b be [2] a6 }

  condition:
    any of them
}