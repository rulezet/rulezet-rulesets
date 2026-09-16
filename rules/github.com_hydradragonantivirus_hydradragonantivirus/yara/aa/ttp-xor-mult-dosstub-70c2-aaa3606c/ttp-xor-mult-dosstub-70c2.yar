rule TTP_XOR_MULT_DOSStub_70c2 {
  strings:
    $key_70c2 = { 24 aa [2] 50 b2 [2] 17 b0 [2] 50 a1 [2] 1e ad [2] 12 a7 [2] 05 ac [2] 1e e2 [2] 23 }

  condition:
    any of them
}