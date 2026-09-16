rule TTP_XOR_MULT_DOSStub_6f95 {
  strings:
    $key_6f95 = { 3b fd [2] 4f e5 [2] 08 e7 [2] 4f f6 [2] 01 fa [2] 0d f0 [2] 1a fb [2] 01 b5 [2] 3c }

  condition:
    any of them
}