rule TTP_XOR_MULT_DOSStub_7f95 {
  strings:
    $key_7f95 = { 2b fd [2] 5f e5 [2] 18 e7 [2] 5f f6 [2] 11 fa [2] 1d f0 [2] 0a fb [2] 11 b5 [2] 2c }

  condition:
    any of them
}