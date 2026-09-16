rule TTP_XOR_MULT_DOSStub_e8c3 {
  strings:
    $key_e8c3 = { bc ab [2] c8 b3 [2] 8f b1 [2] c8 a0 [2] 86 ac [2] 8a a6 [2] 9d ad [2] 86 e3 [2] bb }

  condition:
    any of them
}