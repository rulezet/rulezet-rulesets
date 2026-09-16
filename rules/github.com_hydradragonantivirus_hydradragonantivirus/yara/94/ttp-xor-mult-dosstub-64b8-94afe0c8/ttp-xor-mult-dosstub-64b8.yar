rule TTP_XOR_MULT_DOSStub_64b8 {
  strings:
    $key_64b8 = { 30 d0 [2] 44 c8 [2] 03 ca [2] 44 db [2] 0a d7 [2] 06 dd [2] 11 d6 [2] 0a 98 [2] 37 }

  condition:
    any of them
}