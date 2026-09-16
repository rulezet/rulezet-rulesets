rule TTP_XOR_MULT_DOSStub_3899 {
  strings:
    $key_3899 = { 6c f1 [2] 18 e9 [2] 5f eb [2] 18 fa [2] 56 f6 [2] 5a fc [2] 4d f7 [2] 56 b9 [2] 6b }

  condition:
    any of them
}