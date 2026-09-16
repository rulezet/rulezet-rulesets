rule TTP_XOR_MULT_DOSStub_d4b8 {
  strings:
    $key_d4b8 = { 80 d0 [2] f4 c8 [2] b3 ca [2] f4 db [2] ba d7 [2] b6 dd [2] a1 d6 [2] ba 98 [2] 87 }

  condition:
    any of them
}