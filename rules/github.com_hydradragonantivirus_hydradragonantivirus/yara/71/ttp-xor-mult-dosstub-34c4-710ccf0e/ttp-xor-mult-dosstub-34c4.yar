rule TTP_XOR_MULT_DOSStub_34c4 {
  strings:
    $key_34c4 = { 60 ac [2] 14 b4 [2] 53 b6 [2] 14 a7 [2] 5a ab [2] 56 a1 [2] 41 aa [2] 5a e4 [2] 67 }

  condition:
    any of them
}