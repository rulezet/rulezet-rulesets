rule TTP_XOR_MULT_DOSStub_2f92 {
  strings:
    $key_2f92 = { 7b fa [2] 0f e2 [2] 48 e0 [2] 0f f1 [2] 41 fd [2] 4d f7 [2] 5a fc [2] 41 b2 [2] 7c }

  condition:
    any of them
}