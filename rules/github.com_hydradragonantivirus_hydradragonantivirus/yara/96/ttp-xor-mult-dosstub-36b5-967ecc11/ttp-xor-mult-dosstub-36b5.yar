rule TTP_XOR_MULT_DOSStub_36b5 {
  strings:
    $key_36b5 = { 62 dd [2] 16 c5 [2] 51 c7 [2] 16 d6 [2] 58 da [2] 54 d0 [2] 43 db [2] 58 95 [2] 65 }

  condition:
    any of them
}