rule TTP_XOR_MULT_DOSStub_f5c4 {
  strings:
    $key_f5c4 = { a1 ac [2] d5 b4 [2] 92 b6 [2] d5 a7 [2] 9b ab [2] 97 a1 [2] 80 aa [2] 9b e4 [2] a6 }

  condition:
    any of them
}