rule TTP_XOR_MULT_DOSStub_30c2 {
  strings:
    $key_30c2 = { 64 aa [2] 10 b2 [2] 57 b0 [2] 10 a1 [2] 5e ad [2] 52 a7 [2] 45 ac [2] 5e e2 [2] 63 }

  condition:
    any of them
}