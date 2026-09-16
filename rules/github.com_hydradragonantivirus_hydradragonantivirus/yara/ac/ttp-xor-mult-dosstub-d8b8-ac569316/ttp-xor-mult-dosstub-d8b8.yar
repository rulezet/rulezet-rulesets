rule TTP_XOR_MULT_DOSStub_d8b8 {
  strings:
    $key_d8b8 = { 8c d0 [2] f8 c8 [2] bf ca [2] f8 db [2] b6 d7 [2] ba dd [2] ad d6 [2] b6 98 [2] 8b }

  condition:
    any of them
}