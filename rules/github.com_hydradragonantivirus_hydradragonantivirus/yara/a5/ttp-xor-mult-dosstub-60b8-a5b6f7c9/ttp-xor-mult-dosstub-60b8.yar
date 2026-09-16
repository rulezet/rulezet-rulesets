rule TTP_XOR_MULT_DOSStub_60b8 {
  strings:
    $key_60b8 = { 34 d0 [2] 40 c8 [2] 07 ca [2] 40 db [2] 0e d7 [2] 02 dd [2] 15 d6 [2] 0e 98 [2] 33 }

  condition:
    any of them
}