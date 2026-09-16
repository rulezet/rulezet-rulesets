rule TTP_XOR_MULT_DOSStub_00c4 {
  strings:
    $key_00c4 = { 54 ac [2] 20 b4 [2] 67 b6 [2] 20 a7 [2] 6e ab [2] 62 a1 [2] 75 aa [2] 6e e4 [2] 53 }

  condition:
    any of them
}