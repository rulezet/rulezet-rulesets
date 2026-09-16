rule TTP_XOR_MULT_DOSStub_d0b1 {
  strings:
    $key_d0b1 = { 84 d9 [2] f0 c1 [2] b7 c3 [2] f0 d2 [2] be de [2] b2 d4 [2] a5 df [2] be 91 [2] 83 }

  condition:
    any of them
}