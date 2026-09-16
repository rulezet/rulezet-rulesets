rule TTP_XOR_MULT_DOSStub_0ab8 {
  strings:
    $key_0ab8 = { 5e d0 [2] 2a c8 [2] 6d ca [2] 2a db [2] 64 d7 [2] 68 dd [2] 7f d6 [2] 64 98 [2] 59 }

  condition:
    any of them
}