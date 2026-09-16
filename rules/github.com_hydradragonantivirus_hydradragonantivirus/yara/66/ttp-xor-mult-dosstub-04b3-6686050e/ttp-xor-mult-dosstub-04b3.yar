rule TTP_XOR_MULT_DOSStub_04b3 {
  strings:
    $key_04b3 = { 50 db [2] 24 c3 [2] 63 c1 [2] 24 d0 [2] 6a dc [2] 66 d6 [2] 71 dd [2] 6a 93 [2] 57 }

  condition:
    any of them
}