rule TTP_XOR_MULT_DOSStub_0d9e {
  strings:
    $key_0d9e = { 59 f6 [2] 2d ee [2] 6a ec [2] 2d fd [2] 63 f1 [2] 6f fb [2] 78 f0 [2] 63 be [2] 5e }

  condition:
    any of them
}