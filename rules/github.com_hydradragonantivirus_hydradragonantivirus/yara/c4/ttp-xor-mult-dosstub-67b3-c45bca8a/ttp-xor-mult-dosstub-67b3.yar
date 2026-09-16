rule TTP_XOR_MULT_DOSStub_67b3 {
  strings:
    $key_67b3 = { 33 db [2] 47 c3 [2] 00 c1 [2] 47 d0 [2] 09 dc [2] 05 d6 [2] 12 dd [2] 09 93 [2] 34 }

  condition:
    any of them
}