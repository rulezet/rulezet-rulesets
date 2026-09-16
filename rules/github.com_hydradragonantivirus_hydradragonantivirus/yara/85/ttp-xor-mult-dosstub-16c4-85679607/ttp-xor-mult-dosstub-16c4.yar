rule TTP_XOR_MULT_DOSStub_16c4 {
  strings:
    $key_16c4 = { 42 ac [2] 36 b4 [2] 71 b6 [2] 36 a7 [2] 78 ab [2] 74 a1 [2] 63 aa [2] 78 e4 [2] 45 }

  condition:
    any of them
}