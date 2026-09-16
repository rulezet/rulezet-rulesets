rule TTP_XOR_MULT_DOSStub_14c4 {
  strings:
    $key_14c4 = { 40 ac [2] 34 b4 [2] 73 b6 [2] 34 a7 [2] 7a ab [2] 76 a1 [2] 61 aa [2] 7a e4 [2] 47 }

  condition:
    any of them
}