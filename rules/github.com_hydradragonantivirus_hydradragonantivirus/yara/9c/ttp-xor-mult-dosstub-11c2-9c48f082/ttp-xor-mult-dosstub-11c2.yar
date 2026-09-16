rule TTP_XOR_MULT_DOSStub_11c2 {
  strings:
    $key_11c2 = { 45 aa [2] 31 b2 [2] 76 b0 [2] 31 a1 [2] 7f ad [2] 73 a7 [2] 64 ac [2] 7f e2 [2] 42 }

  condition:
    any of them
}