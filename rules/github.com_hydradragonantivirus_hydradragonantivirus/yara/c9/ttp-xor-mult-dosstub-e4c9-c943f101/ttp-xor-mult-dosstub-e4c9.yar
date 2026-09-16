rule TTP_XOR_MULT_DOSStub_e4c9 {
  strings:
    $key_e4c9 = { b0 a1 [2] c4 b9 [2] 83 bb [2] c4 aa [2] 8a a6 [2] 86 ac [2] 91 a7 [2] 8a e9 [2] b7 }

  condition:
    any of them
}