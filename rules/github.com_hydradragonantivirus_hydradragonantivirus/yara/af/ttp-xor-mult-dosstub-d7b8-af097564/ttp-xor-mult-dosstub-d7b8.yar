rule TTP_XOR_MULT_DOSStub_d7b8 {
  strings:
    $key_d7b8 = { 83 d0 [2] f7 c8 [2] b0 ca [2] f7 db [2] b9 d7 [2] b5 dd [2] a2 d6 [2] b9 98 [2] 84 }

  condition:
    any of them
}