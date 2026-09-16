rule TTP_XOR_MULT_DOSStub_56b8 {
  strings:
    $key_56b8 = { 02 d0 [2] 76 c8 [2] 31 ca [2] 76 db [2] 38 d7 [2] 34 dd [2] 23 d6 [2] 38 98 [2] 05 }

  condition:
    any of them
}