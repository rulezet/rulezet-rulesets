rule TTP_XOR_MULT_DOSStub_2f9e {
  strings:
    $key_2f9e = { 7b f6 [2] 0f ee [2] 48 ec [2] 0f fd [2] 41 f1 [2] 4d fb [2] 5a f0 [2] 41 be [2] 7c }

  condition:
    any of them
}