rule TTP_XOR_MULT_DOSStub_5d9e {
  strings:
    $key_5d9e = { 09 f6 [2] 7d ee [2] 3a ec [2] 7d fd [2] 33 f1 [2] 3f fb [2] 28 f0 [2] 33 be [2] 0e }

  condition:
    any of them
}