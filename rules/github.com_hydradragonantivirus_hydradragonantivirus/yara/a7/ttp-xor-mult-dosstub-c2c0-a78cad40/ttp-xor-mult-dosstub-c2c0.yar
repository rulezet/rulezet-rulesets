rule TTP_XOR_MULT_DOSStub_c2c0 {
  strings:
    $key_c2c0 = { 96 a8 [2] e2 b0 [2] a5 b2 [2] e2 a3 [2] ac af [2] a0 a5 [2] b7 ae [2] ac e0 [2] 91 }

  condition:
    any of them
}