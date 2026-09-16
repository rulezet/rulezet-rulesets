rule TTP_XOR_MULT_DOSStub_45b3 {
  strings:
    $key_45b3 = { 11 db [2] 65 c3 [2] 22 c1 [2] 65 d0 [2] 2b dc [2] 27 d6 [2] 30 dd [2] 2b 93 [2] 16 }

  condition:
    any of them
}