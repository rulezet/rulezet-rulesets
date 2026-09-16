rule TTP_XOR_MULT_DOSStub_4bb8 {
  strings:
    $key_4bb8 = { 1f d0 [2] 6b c8 [2] 2c ca [2] 6b db [2] 25 d7 [2] 29 dd [2] 3e d6 [2] 25 98 [2] 18 }

  condition:
    any of them
}