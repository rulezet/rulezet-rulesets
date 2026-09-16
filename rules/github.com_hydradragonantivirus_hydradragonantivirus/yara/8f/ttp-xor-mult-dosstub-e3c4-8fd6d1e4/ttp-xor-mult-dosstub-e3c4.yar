rule TTP_XOR_MULT_DOSStub_e3c4 {
  strings:
    $key_e3c4 = { b7 ac [2] c3 b4 [2] 84 b6 [2] c3 a7 [2] 8d ab [2] 81 a1 [2] 96 aa [2] 8d e4 [2] b0 }

  condition:
    any of them
}