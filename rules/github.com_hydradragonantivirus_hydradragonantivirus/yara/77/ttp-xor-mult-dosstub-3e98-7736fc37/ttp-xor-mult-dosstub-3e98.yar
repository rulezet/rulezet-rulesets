rule TTP_XOR_MULT_DOSStub_3e98 {
  strings:
    $key_3e98 = { 6a f0 [2] 1e e8 [2] 59 ea [2] 1e fb [2] 50 f7 [2] 5c fd [2] 4b f6 [2] 50 b8 [2] 6d }

  condition:
    any of them
}