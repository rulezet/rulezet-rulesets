rule TTP_XOR_MULT_DOSStub_44c4 {
  strings:
    $key_44c4 = { 10 ac [2] 64 b4 [2] 23 b6 [2] 64 a7 [2] 2a ab [2] 26 a1 [2] 31 aa [2] 2a e4 [2] 17 }

  condition:
    any of them
}