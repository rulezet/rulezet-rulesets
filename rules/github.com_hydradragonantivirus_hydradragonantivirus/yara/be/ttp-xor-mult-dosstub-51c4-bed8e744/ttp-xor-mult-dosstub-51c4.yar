rule TTP_XOR_MULT_DOSStub_51c4 {
  strings:
    $key_51c4 = { 05 ac [2] 71 b4 [2] 36 b6 [2] 71 a7 [2] 3f ab [2] 33 a1 [2] 24 aa [2] 3f e4 [2] 02 }

  condition:
    any of them
}