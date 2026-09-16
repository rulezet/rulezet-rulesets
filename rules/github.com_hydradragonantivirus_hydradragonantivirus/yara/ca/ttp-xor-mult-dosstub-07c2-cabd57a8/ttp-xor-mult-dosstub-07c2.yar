rule TTP_XOR_MULT_DOSStub_07c2 {
  strings:
    $key_07c2 = { 53 aa [2] 27 b2 [2] 60 b0 [2] 27 a1 [2] 69 ad [2] 65 a7 [2] 72 ac [2] 69 e2 [2] 54 }

  condition:
    any of them
}