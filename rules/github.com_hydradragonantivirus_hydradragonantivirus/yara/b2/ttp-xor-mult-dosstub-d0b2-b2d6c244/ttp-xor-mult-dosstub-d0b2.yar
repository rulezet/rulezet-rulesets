rule TTP_XOR_MULT_DOSStub_d0b2 {
  strings:
    $key_d0b2 = { 84 da [2] f0 c2 [2] b7 c0 [2] f0 d1 [2] be dd [2] b2 d7 [2] a5 dc [2] be 92 [2] 83 }

  condition:
    any of them
}