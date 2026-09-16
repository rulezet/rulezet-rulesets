rule TTP_XOR_MULT_DOSStub_20b8 {
  strings:
    $key_20b8 = { 74 d0 [2] 00 c8 [2] 47 ca [2] 00 db [2] 4e d7 [2] 42 dd [2] 55 d6 [2] 4e 98 [2] 73 }

  condition:
    any of them
}