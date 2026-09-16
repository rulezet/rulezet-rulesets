rule TTP_XOR_MULT_DOSStub_01b8 {
  strings:
    $key_01b8 = { 55 d0 [2] 21 c8 [2] 66 ca [2] 21 db [2] 6f d7 [2] 63 dd [2] 74 d6 [2] 6f 98 [2] 52 }

  condition:
    any of them
}