rule TTP_XOR_MULT_DOSStub_36b3 {
  strings:
    $key_36b3 = { 62 db [2] 16 c3 [2] 51 c1 [2] 16 d0 [2] 58 dc [2] 54 d6 [2] 43 dd [2] 58 93 [2] 65 }

  condition:
    any of them
}