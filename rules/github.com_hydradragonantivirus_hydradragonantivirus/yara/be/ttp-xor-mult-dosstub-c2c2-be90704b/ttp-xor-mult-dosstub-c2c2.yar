rule TTP_XOR_MULT_DOSStub_c2c2 {
  strings:
    $key_c2c2 = { 96 aa [2] e2 b2 [2] a5 b0 [2] e2 a1 [2] ac ad [2] a0 a7 [2] b7 ac [2] ac e2 [2] 91 }

  condition:
    any of them
}