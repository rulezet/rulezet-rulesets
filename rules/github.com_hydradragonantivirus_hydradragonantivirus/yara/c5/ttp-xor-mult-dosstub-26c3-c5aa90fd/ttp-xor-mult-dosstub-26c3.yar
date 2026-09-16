rule TTP_XOR_MULT_DOSStub_26c3 {
  strings:
    $key_26c3 = { 72 ab [2] 06 b3 [2] 41 b1 [2] 06 a0 [2] 48 ac [2] 44 a6 [2] 53 ad [2] 48 e3 [2] 75 }

  condition:
    any of them
}