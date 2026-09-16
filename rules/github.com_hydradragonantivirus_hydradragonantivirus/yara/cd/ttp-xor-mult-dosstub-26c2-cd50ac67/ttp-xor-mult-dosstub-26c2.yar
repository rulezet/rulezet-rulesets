rule TTP_XOR_MULT_DOSStub_26c2 {
  strings:
    $key_26c2 = { 72 aa [2] 06 b2 [2] 41 b0 [2] 06 a1 [2] 48 ad [2] 44 a7 [2] 53 ac [2] 48 e2 [2] 75 }

  condition:
    any of them
}