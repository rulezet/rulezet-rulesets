rule TTP_XOR_MULT_DOSStub_17b8 {
  strings:
    $key_17b8 = { 43 d0 [2] 37 c8 [2] 70 ca [2] 37 db [2] 79 d7 [2] 75 dd [2] 62 d6 [2] 79 98 [2] 44 }

  condition:
    any of them
}