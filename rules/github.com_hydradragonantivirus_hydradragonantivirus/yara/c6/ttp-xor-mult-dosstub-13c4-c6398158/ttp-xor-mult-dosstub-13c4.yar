rule TTP_XOR_MULT_DOSStub_13c4 {
  strings:
    $key_13c4 = { 47 ac [2] 33 b4 [2] 74 b6 [2] 33 a7 [2] 7d ab [2] 71 a1 [2] 66 aa [2] 7d e4 [2] 40 }

  condition:
    any of them
}