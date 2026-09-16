rule TTP_XOR_MULT_DOSStub_d4b3 {
  strings:
    $key_d4b3 = { 80 db [2] f4 c3 [2] b3 c1 [2] f4 d0 [2] ba dc [2] b6 d6 [2] a1 dd [2] ba 93 [2] 87 }

  condition:
    any of them
}