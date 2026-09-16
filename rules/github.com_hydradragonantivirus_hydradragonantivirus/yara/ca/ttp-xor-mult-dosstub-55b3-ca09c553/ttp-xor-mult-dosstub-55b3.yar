rule TTP_XOR_MULT_DOSStub_55b3 {
  strings:
    $key_55b3 = { 01 db [2] 75 c3 [2] 32 c1 [2] 75 d0 [2] 3b dc [2] 37 d6 [2] 20 dd [2] 3b 93 [2] 06 }

  condition:
    any of them
}