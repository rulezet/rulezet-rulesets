rule TTP_XOR_MULT_DOSStub_e3c2 {
  strings:
    $key_e3c2 = { b7 aa [2] c3 b2 [2] 84 b0 [2] c3 a1 [2] 8d ad [2] 81 a7 [2] 96 ac [2] 8d e2 [2] b0 }

  condition:
    any of them
}