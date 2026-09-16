rule TTP_XOR_MULT_DOSStub_7c98 {
  strings:
    $key_7c98 = { 28 f0 [2] 5c e8 [2] 1b ea [2] 5c fb [2] 12 f7 [2] 1e fd [2] 09 f6 [2] 12 b8 [2] 2f }

  condition:
    any of them
}