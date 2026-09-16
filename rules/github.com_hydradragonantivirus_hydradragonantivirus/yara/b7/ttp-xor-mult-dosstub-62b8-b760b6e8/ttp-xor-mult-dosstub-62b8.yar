rule TTP_XOR_MULT_DOSStub_62b8 {
  strings:
    $key_62b8 = { 36 d0 [2] 42 c8 [2] 05 ca [2] 42 db [2] 0c d7 [2] 00 dd [2] 17 d6 [2] 0c 98 [2] 31 }

  condition:
    any of them
}