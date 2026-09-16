rule TTP_XOR_MULT_DOSStub_47b5 {
  strings:
    $key_47b5 = { 13 dd [2] 67 c5 [2] 20 c7 [2] 67 d6 [2] 29 da [2] 25 d0 [2] 32 db [2] 29 95 [2] 14 }

  condition:
    any of them
}