rule TTP_XOR_MULT_DOSStub_09c3 {
  strings:
    $key_09c3 = { 5d ab [2] 29 b3 [2] 6e b1 [2] 29 a0 [2] 67 ac [2] 6b a6 [2] 7c ad [2] 67 e3 [2] 5a }

  condition:
    any of them
}