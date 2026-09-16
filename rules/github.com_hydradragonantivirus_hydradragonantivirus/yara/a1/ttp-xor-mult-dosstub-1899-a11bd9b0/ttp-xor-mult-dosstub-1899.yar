rule TTP_XOR_MULT_DOSStub_1899 {
  strings:
    $key_1899 = { 4c f1 [2] 38 e9 [2] 7f eb [2] 38 fa [2] 76 f6 [2] 7a fc [2] 6d f7 [2] 76 b9 [2] 4b }

  condition:
    any of them
}