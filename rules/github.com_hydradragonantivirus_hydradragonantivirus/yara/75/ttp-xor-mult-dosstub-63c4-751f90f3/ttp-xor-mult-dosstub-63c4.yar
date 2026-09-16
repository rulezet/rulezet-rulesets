rule TTP_XOR_MULT_DOSStub_63c4 {
  strings:
    $key_63c4 = { 37 ac [2] 43 b4 [2] 04 b6 [2] 43 a7 [2] 0d ab [2] 01 a1 [2] 16 aa [2] 0d e4 [2] 30 }

  condition:
    any of them
}