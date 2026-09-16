rule TTP_XOR_MULT_DOSStub_d0b3 {
  strings:
    $key_d0b3 = { 84 db [2] f0 c3 [2] b7 c1 [2] f0 d0 [2] be dc [2] b2 d6 [2] a5 dd [2] be 93 [2] 83 }

  condition:
    any of them
}