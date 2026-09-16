rule TTP_XOR_MULT_DOSStub_7999 {
  strings:
    $key_7999 = { 2d f1 [2] 59 e9 [2] 1e eb [2] 59 fa [2] 17 f6 [2] 1b fc [2] 0c f7 [2] 17 b9 [2] 2a }

  condition:
    any of them
}