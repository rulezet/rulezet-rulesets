rule TTP_XOR_MULT_DOSStub_71c4 {
  strings:
    $key_71c4 = { 25 ac [2] 51 b4 [2] 16 b6 [2] 51 a7 [2] 1f ab [2] 13 a1 [2] 04 aa [2] 1f e4 [2] 22 }

  condition:
    any of them
}