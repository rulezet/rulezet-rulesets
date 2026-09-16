rule TTP_XOR_MULT_DOSStub_11c4 {
  strings:
    $key_11c4 = { 45 ac [2] 31 b4 [2] 76 b6 [2] 31 a7 [2] 7f ab [2] 73 a1 [2] 64 aa [2] 7f e4 [2] 42 }

  condition:
    any of them
}