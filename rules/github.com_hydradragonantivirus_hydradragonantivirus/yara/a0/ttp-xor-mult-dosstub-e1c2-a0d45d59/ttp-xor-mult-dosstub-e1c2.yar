rule TTP_XOR_MULT_DOSStub_e1c2 {
  strings:
    $key_e1c2 = { b5 aa [2] c1 b2 [2] 86 b0 [2] c1 a1 [2] 8f ad [2] 83 a7 [2] 94 ac [2] 8f e2 [2] b2 }

  condition:
    any of them
}