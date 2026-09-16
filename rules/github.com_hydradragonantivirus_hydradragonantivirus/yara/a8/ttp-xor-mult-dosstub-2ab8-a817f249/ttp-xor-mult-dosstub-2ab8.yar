rule TTP_XOR_MULT_DOSStub_2ab8 {
  strings:
    $key_2ab8 = { 7e d0 [2] 0a c8 [2] 4d ca [2] 0a db [2] 44 d7 [2] 48 dd [2] 5f d6 [2] 44 98 [2] 79 }

  condition:
    any of them
}