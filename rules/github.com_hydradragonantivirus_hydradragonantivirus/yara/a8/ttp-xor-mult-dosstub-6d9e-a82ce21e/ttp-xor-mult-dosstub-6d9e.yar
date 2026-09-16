rule TTP_XOR_MULT_DOSStub_6d9e {
  strings:
    $key_6d9e = { 39 f6 [2] 4d ee [2] 0a ec [2] 4d fd [2] 03 f1 [2] 0f fb [2] 18 f0 [2] 03 be [2] 3e }

  condition:
    any of them
}