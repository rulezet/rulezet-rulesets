rule TTP_XOR_MULT_DOSStub_e899 {
  strings:
    $key_e899 = { bc f1 [2] c8 e9 [2] 8f eb [2] c8 fa [2] 86 f6 [2] 8a fc [2] 9d f7 [2] 86 b9 [2] bb }

  condition:
    any of them
}