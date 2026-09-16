rule TTP_XOR_MULT_DOSStub_e0c4 {
  strings:
    $key_e0c4 = { b4 ac [2] c0 b4 [2] 87 b6 [2] c0 a7 [2] 8e ab [2] 82 a1 [2] 95 aa [2] 8e e4 [2] b3 }

  condition:
    any of them
}