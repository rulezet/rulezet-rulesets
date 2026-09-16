rule TTP_XOR_MULT_DOSStub_3d9e {
  strings:
    $key_3d9e = { 69 f6 [2] 1d ee [2] 5a ec [2] 1d fd [2] 53 f1 [2] 5f fb [2] 48 f0 [2] 53 be [2] 6e }

  condition:
    any of them
}