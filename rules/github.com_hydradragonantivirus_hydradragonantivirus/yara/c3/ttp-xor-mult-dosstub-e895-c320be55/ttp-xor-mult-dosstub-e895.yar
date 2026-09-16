rule TTP_XOR_MULT_DOSStub_e895 {
  strings:
    $key_e895 = { bc fd [2] c8 e5 [2] 8f e7 [2] c8 f6 [2] 86 fa [2] 8a f0 [2] 9d fb [2] 86 b5 [2] bb }

  condition:
    any of them
}