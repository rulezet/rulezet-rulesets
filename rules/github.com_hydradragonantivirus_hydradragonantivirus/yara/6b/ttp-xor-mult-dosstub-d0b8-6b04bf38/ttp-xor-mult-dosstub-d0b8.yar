rule TTP_XOR_MULT_DOSStub_d0b8 {
  strings:
    $key_d0b8 = { 84 d0 [2] f0 c8 [2] b7 ca [2] f0 db [2] be d7 [2] b2 dd [2] a5 d6 [2] be 98 [2] 83 }

  condition:
    any of them
}