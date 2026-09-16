rule TTP_XOR_MULT_DOSStub_41b8 {
  strings:
    $key_41b8 = { 15 d0 [2] 61 c8 [2] 26 ca [2] 61 db [2] 2f d7 [2] 23 dd [2] 34 d6 [2] 2f 98 [2] 12 }

  condition:
    any of them
}