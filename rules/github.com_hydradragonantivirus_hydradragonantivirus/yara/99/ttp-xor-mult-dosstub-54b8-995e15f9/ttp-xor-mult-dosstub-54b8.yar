rule TTP_XOR_MULT_DOSStub_54b8 {
  strings:
    $key_54b8 = { 00 d0 [2] 74 c8 [2] 33 ca [2] 74 db [2] 3a d7 [2] 36 dd [2] 21 d6 [2] 3a 98 [2] 07 }

  condition:
    any of them
}