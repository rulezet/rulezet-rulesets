rule TTP_XOR_MULT_DOSStub_47b8 {
  strings:
    $key_47b8 = { 13 d0 [2] 67 c8 [2] 20 ca [2] 67 db [2] 29 d7 [2] 25 dd [2] 32 d6 [2] 29 98 [2] 14 }

  condition:
    any of them
}