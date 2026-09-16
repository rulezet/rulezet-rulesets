rule TTP_XOR_MULT_DOSStub_e892 {
  strings:
    $key_e892 = { bc fa [2] c8 e2 [2] 8f e0 [2] c8 f1 [2] 86 fd [2] 8a f7 [2] 9d fc [2] 86 b2 [2] bb }

  condition:
    any of them
}