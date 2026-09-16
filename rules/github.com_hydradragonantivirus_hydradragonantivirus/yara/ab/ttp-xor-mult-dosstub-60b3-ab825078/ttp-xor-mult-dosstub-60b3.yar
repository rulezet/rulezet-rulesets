rule TTP_XOR_MULT_DOSStub_60b3 {
  strings:
    $key_60b3 = { 34 db [2] 40 c3 [2] 07 c1 [2] 40 d0 [2] 0e dc [2] 02 d6 [2] 15 dd [2] 0e 93 [2] 33 }

  condition:
    any of them
}