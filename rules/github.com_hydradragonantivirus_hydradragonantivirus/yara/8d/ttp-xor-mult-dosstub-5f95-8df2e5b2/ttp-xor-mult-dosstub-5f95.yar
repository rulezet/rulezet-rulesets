rule TTP_XOR_MULT_DOSStub_5f95 {
  strings:
    $key_5f95 = { 0b fd [2] 7f e5 [2] 38 e7 [2] 7f f6 [2] 31 fa [2] 3d f0 [2] 2a fb [2] 31 b5 [2] 0c }

  condition:
    any of them
}