rule TTP_XOR_MULT_DOSStub_67b5 {
  strings:
    $key_67b5 = { 33 dd [2] 47 c5 [2] 00 c7 [2] 47 d6 [2] 09 da [2] 05 d0 [2] 12 db [2] 09 95 [2] 34 }

  condition:
    any of them
}