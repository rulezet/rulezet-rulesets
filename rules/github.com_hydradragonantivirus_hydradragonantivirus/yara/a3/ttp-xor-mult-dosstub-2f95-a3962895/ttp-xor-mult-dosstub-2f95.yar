rule TTP_XOR_MULT_DOSStub_2f95 {
  strings:
    $key_2f95 = { 7b fd [2] 0f e5 [2] 48 e7 [2] 0f f6 [2] 41 fa [2] 4d f0 [2] 5a fb [2] 41 b5 [2] 7c }

  condition:
    any of them
}