rule TTP_XOR_MULT_DOSStub_04b8 {
  strings:
    $key_04b8 = { 50 d0 [2] 24 c8 [2] 63 ca [2] 24 db [2] 6a d7 [2] 66 dd [2] 71 d6 [2] 6a 98 [2] 57 }

  condition:
    any of them
}