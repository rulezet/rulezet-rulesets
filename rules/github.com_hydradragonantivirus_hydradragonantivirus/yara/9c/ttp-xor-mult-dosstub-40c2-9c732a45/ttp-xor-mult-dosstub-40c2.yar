rule TTP_XOR_MULT_DOSStub_40c2 {
  strings:
    $key_40c2 = { 14 aa [2] 60 b2 [2] 27 b0 [2] 60 a1 [2] 2e ad [2] 22 a7 [2] 35 ac [2] 2e e2 [2] 13 }

  condition:
    any of them
}