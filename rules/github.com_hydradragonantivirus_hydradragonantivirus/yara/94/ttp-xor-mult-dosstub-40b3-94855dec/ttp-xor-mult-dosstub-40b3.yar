rule TTP_XOR_MULT_DOSStub_40b3 {
  strings:
    $key_40b3 = { 14 db [2] 60 c3 [2] 27 c1 [2] 60 d0 [2] 2e dc [2] 22 d6 [2] 35 dd [2] 2e 93 [2] 13 }

  condition:
    any of them
}