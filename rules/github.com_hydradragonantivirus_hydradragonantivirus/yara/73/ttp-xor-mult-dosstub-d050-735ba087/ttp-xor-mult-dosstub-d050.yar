rule TTP_XOR_MULT_DOSStub_d050 {
  strings:
    $key_d050 = { 84 38 [2] f0 20 [2] b7 22 [2] f0 33 [2] be 3f [2] b2 35 [2] a5 3e [2] be 70 [2] 83 }

  condition:
    any of them
}