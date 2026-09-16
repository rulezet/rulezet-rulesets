rule TTP_XOR_MULT_DOSStub_e8d4 {
  strings:
    $key_e8d4 = { bc bc [2] c8 a4 [2] 8f a6 [2] c8 b7 [2] 86 bb [2] 8a b1 [2] 9d ba [2] 86 f4 [2] bb }

  condition:
    any of them
}