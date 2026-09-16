rule TTP_XOR_MULT_DOSStub_c5c4 {
  strings:
    $key_c5c4 = { 91 ac [2] e5 b4 [2] a2 b6 [2] e5 a7 [2] ab ab [2] a7 a1 [2] b0 aa [2] ab e4 [2] 96 }

  condition:
    any of them
}