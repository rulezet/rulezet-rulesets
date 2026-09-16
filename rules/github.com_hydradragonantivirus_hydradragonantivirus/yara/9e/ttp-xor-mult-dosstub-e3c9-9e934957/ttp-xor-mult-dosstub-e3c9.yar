rule TTP_XOR_MULT_DOSStub_e3c9 {
  strings:
    $key_e3c9 = { b7 a1 [2] c3 b9 [2] 84 bb [2] c3 aa [2] 8d a6 [2] 81 ac [2] 96 a7 [2] 8d e9 [2] b0 }

  condition:
    any of them
}