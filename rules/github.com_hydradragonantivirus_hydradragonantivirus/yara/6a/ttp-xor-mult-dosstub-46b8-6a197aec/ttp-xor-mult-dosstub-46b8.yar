rule TTP_XOR_MULT_DOSStub_46b8 {
  strings:
    $key_46b8 = { 12 d0 [2] 66 c8 [2] 21 ca [2] 66 db [2] 28 d7 [2] 24 dd [2] 33 d6 [2] 28 98 [2] 15 }

  condition:
    any of them
}