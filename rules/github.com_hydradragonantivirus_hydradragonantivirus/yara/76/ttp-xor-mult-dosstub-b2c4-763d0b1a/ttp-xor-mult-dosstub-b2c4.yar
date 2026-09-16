rule TTP_XOR_MULT_DOSStub_b2c4 {
  strings:
    $key_b2c4 = { e6 ac [2] 92 b4 [2] d5 b6 [2] 92 a7 [2] dc ab [2] d0 a1 [2] c7 aa [2] dc e4 [2] e1 }

  condition:
    any of them
}