rule TTP_XOR_MULT_DOSStub_c2c4 {
  strings:
    $key_c2c4 = { 96 ac [2] e2 b4 [2] a5 b6 [2] e2 a7 [2] ac ab [2] a0 a1 [2] b7 aa [2] ac e4 [2] 91 }

  condition:
    any of them
}