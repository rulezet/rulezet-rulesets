rule TTP_XOR_MULT_DOSStub_7f98 {
  strings:
    $key_7f98 = { 2b f0 [2] 5f e8 [2] 18 ea [2] 5f fb [2] 11 f7 [2] 1d fd [2] 0a f6 [2] 11 b8 [2] 2c }

  condition:
    any of them
}