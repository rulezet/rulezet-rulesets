rule TTP_XOR_MULT_DOSStub_64b3 {
  strings:
    $key_64b3 = { 30 db [2] 44 c3 [2] 03 c1 [2] 44 d0 [2] 0a dc [2] 06 d6 [2] 11 dd [2] 0a 93 [2] 37 }

  condition:
    any of them
}