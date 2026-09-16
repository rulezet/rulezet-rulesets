rule TTP_XOR_MULT_DOSStub_59c3 {
  strings:
    $key_59c3 = { 0d ab [2] 79 b3 [2] 3e b1 [2] 79 a0 [2] 37 ac [2] 3b a6 [2] 2c ad [2] 37 e3 [2] 0a }

  condition:
    any of them
}