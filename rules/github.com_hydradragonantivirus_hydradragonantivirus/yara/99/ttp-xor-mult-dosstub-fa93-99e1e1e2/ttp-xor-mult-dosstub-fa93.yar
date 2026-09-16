rule TTP_XOR_MULT_DOSStub_fa93 {
  strings:
    $key_fa93 = { ae fb [2] da e3 [2] 9d e1 [2] da f0 [2] 94 fc [2] 98 f6 [2] 8f fd [2] 94 b3 [2] a9 }

  condition:
    any of them
}