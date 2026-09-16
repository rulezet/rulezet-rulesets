rule TTP_XOR_MULT_DOSStub_e7b5 {
  strings:
    $key_e7b5 = { b3 dd [2] c7 c5 [2] 80 c7 [2] c7 d6 [2] 89 da [2] 85 d0 [2] 92 db [2] 89 95 [2] b4 }

  condition:
    any of them
}