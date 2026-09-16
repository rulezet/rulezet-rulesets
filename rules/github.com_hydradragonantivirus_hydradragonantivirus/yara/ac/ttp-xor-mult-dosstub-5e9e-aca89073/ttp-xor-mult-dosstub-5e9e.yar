rule TTP_XOR_MULT_DOSStub_5e9e {
  strings:
    $key_5e9e = { 0a f6 [2] 7e ee [2] 39 ec [2] 7e fd [2] 30 f1 [2] 3c fb [2] 2b f0 [2] 30 be [2] 0d }

  condition:
    any of them
}