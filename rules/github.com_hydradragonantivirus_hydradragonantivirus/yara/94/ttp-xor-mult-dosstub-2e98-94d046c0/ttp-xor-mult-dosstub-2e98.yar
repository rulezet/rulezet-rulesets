rule TTP_XOR_MULT_DOSStub_2e98 {
  strings:
    $key_2e98 = { 7a f0 [2] 0e e8 [2] 49 ea [2] 0e fb [2] 40 f7 [2] 4c fd [2] 5b f6 [2] 40 b8 [2] 7d }

  condition:
    any of them
}