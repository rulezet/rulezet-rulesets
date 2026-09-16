rule TTP_XOR_MULT_DOSStub_65c4 {
  strings:
    $key_65c4 = { 31 ac [2] 45 b4 [2] 02 b6 [2] 45 a7 [2] 0b ab [2] 07 a1 [2] 10 aa [2] 0b e4 [2] 36 }

  condition:
    any of them
}