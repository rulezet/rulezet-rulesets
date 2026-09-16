rule TTP_XOR_MULT_DOSStub_01c4 {
  strings:
    $key_01c4 = { 55 ac [2] 21 b4 [2] 66 b6 [2] 21 a7 [2] 6f ab [2] 63 a1 [2] 74 aa [2] 6f e4 [2] 52 }

  condition:
    any of them
}