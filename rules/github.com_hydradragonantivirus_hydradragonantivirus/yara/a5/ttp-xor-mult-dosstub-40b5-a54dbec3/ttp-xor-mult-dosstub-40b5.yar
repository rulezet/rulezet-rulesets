rule TTP_XOR_MULT_DOSStub_40b5 {
  strings:
    $key_40b5 = { 14 dd [2] 60 c5 [2] 27 c7 [2] 60 d6 [2] 2e da [2] 22 d0 [2] 35 db [2] 2e 95 [2] 13 }

  condition:
    any of them
}