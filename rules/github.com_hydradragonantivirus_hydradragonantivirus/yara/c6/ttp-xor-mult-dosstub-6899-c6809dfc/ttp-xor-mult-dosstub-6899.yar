rule TTP_XOR_MULT_DOSStub_6899 {
  strings:
    $key_6899 = { 3c f1 [2] 48 e9 [2] 0f eb [2] 48 fa [2] 06 f6 [2] 0a fc [2] 1d f7 [2] 06 b9 [2] 3b }

  condition:
    any of them
}