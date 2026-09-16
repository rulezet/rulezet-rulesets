rule TTP_XOR_MULT_DOSStub_30c4 {
  strings:
    $key_30c4 = { 64 ac [2] 10 b4 [2] 57 b6 [2] 10 a7 [2] 5e ab [2] 52 a1 [2] 45 aa [2] 5e e4 [2] 63 }

  condition:
    any of them
}