rule TTP_XOR_MULT_DOSStub_1e98 {
  strings:
    $key_1e98 = { 4a f0 [2] 3e e8 [2] 79 ea [2] 3e fb [2] 70 f7 [2] 7c fd [2] 6b f6 [2] 70 b8 [2] 4d }

  condition:
    any of them
}