rule TTP_XOR_MULT_DOSStub_6a93 {
  strings:
    $key_6a93 = { 3e fb [2] 4a e3 [2] 0d e1 [2] 4a f0 [2] 04 fc [2] 08 f6 [2] 1f fd [2] 04 b3 [2] 39 }

  condition:
    any of them
}