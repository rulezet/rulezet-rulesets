rule TTP_XOR_MULT_DOSStub_25c2 {
  strings:
    $key_25c2 = { 71 aa [2] 05 b2 [2] 42 b0 [2] 05 a1 [2] 4b ad [2] 47 a7 [2] 50 ac [2] 4b e2 [2] 76 }

  condition:
    any of them
}