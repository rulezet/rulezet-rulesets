rule TTP_XOR_MULT_DOSStub_0e9e {
  strings:
    $key_0e9e = { 5a f6 [2] 2e ee [2] 69 ec [2] 2e fd [2] 60 f1 [2] 6c fb [2] 7b f0 [2] 60 be [2] 5d }

  condition:
    any of them
}