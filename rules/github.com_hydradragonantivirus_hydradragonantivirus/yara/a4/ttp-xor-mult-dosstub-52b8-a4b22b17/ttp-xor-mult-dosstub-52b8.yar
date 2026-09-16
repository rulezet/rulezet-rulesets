rule TTP_XOR_MULT_DOSStub_52b8 {
  strings:
    $key_52b8 = { 06 d0 [2] 72 c8 [2] 35 ca [2] 72 db [2] 3c d7 [2] 30 dd [2] 27 d6 [2] 3c 98 [2] 01 }

  condition:
    any of them
}