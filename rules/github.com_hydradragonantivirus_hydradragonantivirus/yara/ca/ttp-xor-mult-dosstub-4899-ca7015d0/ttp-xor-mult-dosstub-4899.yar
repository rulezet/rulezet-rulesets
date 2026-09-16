rule TTP_XOR_MULT_DOSStub_4899 {
  strings:
    $key_4899 = { 1c f1 [2] 68 e9 [2] 2f eb [2] 68 fa [2] 26 f6 [2] 2a fc [2] 3d f7 [2] 26 b9 [2] 1b }

  condition:
    any of them
}