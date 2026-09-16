rule TTP_XOR_MULT_DOSStub_16c2 {
  strings:
    $key_16c2 = { 42 aa [2] 36 b2 [2] 71 b0 [2] 36 a1 [2] 78 ad [2] 74 a7 [2] 63 ac [2] 78 e2 [2] 45 }

  condition:
    any of them
}