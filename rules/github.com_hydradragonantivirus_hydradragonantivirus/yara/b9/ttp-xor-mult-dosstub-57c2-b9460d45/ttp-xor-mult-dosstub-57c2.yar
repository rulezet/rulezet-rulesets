rule TTP_XOR_MULT_DOSStub_57c2 {
  strings:
    $key_57c2 = { 03 aa [2] 77 b2 [2] 30 b0 [2] 77 a1 [2] 39 ad [2] 35 a7 [2] 22 ac [2] 39 e2 [2] 04 }

  condition:
    any of them
}