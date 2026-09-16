rule TTP_XOR_MULT_DOSStub_24c2 {
  strings:
    $key_24c2 = { 70 aa [2] 04 b2 [2] 43 b0 [2] 04 a1 [2] 4a ad [2] 46 a7 [2] 51 ac [2] 4a e2 [2] 77 }

  condition:
    any of them
}