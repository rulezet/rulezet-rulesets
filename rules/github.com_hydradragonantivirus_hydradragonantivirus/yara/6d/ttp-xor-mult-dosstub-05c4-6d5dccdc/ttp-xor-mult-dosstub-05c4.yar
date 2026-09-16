rule TTP_XOR_MULT_DOSStub_05c4 {
  strings:
    $key_05c4 = { 51 ac [2] 25 b4 [2] 62 b6 [2] 25 a7 [2] 6b ab [2] 67 a1 [2] 70 aa [2] 6b e4 [2] 56 }

  condition:
    any of them
}