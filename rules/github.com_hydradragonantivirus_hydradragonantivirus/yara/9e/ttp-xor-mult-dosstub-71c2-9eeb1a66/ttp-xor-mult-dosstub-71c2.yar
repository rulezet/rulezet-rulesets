rule TTP_XOR_MULT_DOSStub_71c2 {
  strings:
    $key_71c2 = { 25 aa [2] 51 b2 [2] 16 b0 [2] 51 a1 [2] 1f ad [2] 13 a7 [2] 04 ac [2] 1f e2 [2] 22 }

  condition:
    any of them
}