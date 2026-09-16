rule TTP_XOR_MULT_DOSStub_32c4 {
  strings:
    $key_32c4 = { 66 ac [2] 12 b4 [2] 55 b6 [2] 12 a7 [2] 5c ab [2] 50 a1 [2] 47 aa [2] 5c e4 [2] 61 }

  condition:
    any of them
}