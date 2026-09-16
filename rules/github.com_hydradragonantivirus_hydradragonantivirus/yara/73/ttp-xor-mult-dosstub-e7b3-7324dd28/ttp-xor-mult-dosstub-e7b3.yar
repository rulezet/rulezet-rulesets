rule TTP_XOR_MULT_DOSStub_e7b3 {
  strings:
    $key_e7b3 = { b3 db [2] c7 c3 [2] 80 c1 [2] c7 d0 [2] 89 dc [2] 85 d6 [2] 92 dd [2] 89 93 [2] b4 }

  condition:
    any of them
}