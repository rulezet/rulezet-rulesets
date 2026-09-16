rule TTP_XOR_MULT_DOSStub_e0c9 {
  strings:
    $key_e0c9 = { b4 a1 [2] c0 b9 [2] 87 bb [2] c0 aa [2] 8e a6 [2] 82 ac [2] 95 a7 [2] 8e e9 [2] b3 }

  condition:
    any of them
}