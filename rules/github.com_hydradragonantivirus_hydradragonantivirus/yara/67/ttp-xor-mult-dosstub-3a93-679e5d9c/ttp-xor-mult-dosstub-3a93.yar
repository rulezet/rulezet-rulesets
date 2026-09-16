rule TTP_XOR_MULT_DOSStub_3a93 {
  strings:
    $key_3a93 = { 6e fb [2] 1a e3 [2] 5d e1 [2] 1a f0 [2] 54 fc [2] 58 f6 [2] 4f fd [2] 54 b3 [2] 69 }

  condition:
    any of them
}