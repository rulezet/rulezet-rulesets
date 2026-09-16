rule TTP_XOR_MULT_DOSStub_2ac3 {
  strings:
    $key_2ac3 = { 7e ab [2] 0a b3 [2] 4d b1 [2] 0a a0 [2] 44 ac [2] 48 a6 [2] 5f ad [2] 44 e3 [2] 79 }

  condition:
    any of them
}