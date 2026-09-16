rule TTP_XOR_MULT_DOSStub_e1c9 {
  strings:
    $key_e1c9 = { b5 a1 [2] c1 b9 [2] 86 bb [2] c1 aa [2] 8f a6 [2] 83 ac [2] 94 a7 [2] 8f e9 [2] b2 }

  condition:
    any of them
}