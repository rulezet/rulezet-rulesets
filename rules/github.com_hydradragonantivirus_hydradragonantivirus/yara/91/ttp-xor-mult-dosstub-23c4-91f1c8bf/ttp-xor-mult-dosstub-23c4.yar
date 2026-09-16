rule TTP_XOR_MULT_DOSStub_23c4 {
  strings:
    $key_23c4 = { 77 ac [2] 03 b4 [2] 44 b6 [2] 03 a7 [2] 4d ab [2] 41 a1 [2] 56 aa [2] 4d e4 [2] 70 }

  condition:
    any of them
}