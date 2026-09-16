rule TTP_XOR_MULT_DOSStub_72c4 {
  strings:
    $key_72c4 = { 26 ac [2] 52 b4 [2] 15 b6 [2] 52 a7 [2] 1c ab [2] 10 a1 [2] 07 aa [2] 1c e4 [2] 21 }

  condition:
    any of them
}