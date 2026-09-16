rule TTP_XOR_MULT_DOSStub_14b3 {
  strings:
    $key_14b3 = { 40 db [2] 34 c3 [2] 73 c1 [2] 34 d0 [2] 7a dc [2] 76 d6 [2] 61 dd [2] 7a 93 [2] 47 }

  condition:
    any of them
}