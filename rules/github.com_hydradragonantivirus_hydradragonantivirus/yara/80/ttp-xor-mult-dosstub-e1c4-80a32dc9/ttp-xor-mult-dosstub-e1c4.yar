rule TTP_XOR_MULT_DOSStub_e1c4 {
  strings:
    $key_e1c4 = { b5 ac [2] c1 b4 [2] 86 b6 [2] c1 a7 [2] 8f ab [2] 83 a1 [2] 94 aa [2] 8f e4 [2] b2 }

  condition:
    any of them
}