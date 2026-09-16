rule TTP_XOR_MULT_DOSStub_0e98 {
  strings:
    $key_0e98 = { 5a f0 [2] 2e e8 [2] 69 ea [2] 2e fb [2] 60 f7 [2] 6c fd [2] 7b f6 [2] 60 b8 [2] 5d }

  condition:
    any of them
}