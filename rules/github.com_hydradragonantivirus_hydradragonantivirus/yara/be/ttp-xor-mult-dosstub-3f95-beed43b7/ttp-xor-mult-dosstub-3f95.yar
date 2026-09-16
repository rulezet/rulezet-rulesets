rule TTP_XOR_MULT_DOSStub_3f95 {
  strings:
    $key_3f95 = { 6b fd [2] 1f e5 [2] 58 e7 [2] 1f f6 [2] 51 fa [2] 5d f0 [2] 4a fb [2] 51 b5 [2] 6c }

  condition:
    any of them
}