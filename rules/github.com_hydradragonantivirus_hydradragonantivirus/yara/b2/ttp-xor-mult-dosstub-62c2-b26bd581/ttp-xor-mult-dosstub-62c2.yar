rule TTP_XOR_MULT_DOSStub_62c2 {
  strings:
    $key_62c2 = { 36 aa [2] 42 b2 [2] 05 b0 [2] 42 a1 [2] 0c ad [2] 00 a7 [2] 17 ac [2] 0c e2 [2] 31 }

  condition:
    any of them
}