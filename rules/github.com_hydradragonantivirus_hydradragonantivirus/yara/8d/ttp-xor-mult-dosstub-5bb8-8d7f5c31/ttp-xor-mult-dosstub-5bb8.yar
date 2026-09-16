rule TTP_XOR_MULT_DOSStub_5bb8 {
  strings:
    $key_5bb8 = { 0f d0 [2] 7b c8 [2] 3c ca [2] 7b db [2] 35 d7 [2] 39 dd [2] 2e d6 [2] 35 98 [2] 08 }

  condition:
    any of them
}