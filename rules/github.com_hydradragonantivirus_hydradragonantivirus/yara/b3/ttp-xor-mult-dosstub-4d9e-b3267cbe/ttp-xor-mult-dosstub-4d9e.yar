rule TTP_XOR_MULT_DOSStub_4d9e {
  strings:
    $key_4d9e = { 19 f6 [2] 6d ee [2] 2a ec [2] 6d fd [2] 23 f1 [2] 2f fb [2] 38 f0 [2] 23 be [2] 1e }

  condition:
    any of them
}