rule TTP_XOR_MULT_DOSStub_00b8 {
  strings:
    $key_00b8 = { 54 d0 [2] 20 c8 [2] 67 ca [2] 20 db [2] 6e d7 [2] 62 dd [2] 75 d6 [2] 6e 98 [2] 53 }

  condition:
    any of them
}