rule TTP_XOR_MULT_DOSStub_74b8 {
  strings:
    $key_74b8 = { 20 d0 [2] 54 c8 [2] 13 ca [2] 54 db [2] 1a d7 [2] 16 dd [2] 01 d6 [2] 1a 98 [2] 27 }

  condition:
    any of them
}