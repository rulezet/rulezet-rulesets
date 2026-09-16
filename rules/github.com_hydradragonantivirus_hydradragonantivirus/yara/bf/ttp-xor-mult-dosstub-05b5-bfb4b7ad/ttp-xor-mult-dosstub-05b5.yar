rule TTP_XOR_MULT_DOSStub_05b5 {
  strings:
    $key_05b5 = { 51 dd [2] 25 c5 [2] 62 c7 [2] 25 d6 [2] 6b da [2] 67 d0 [2] 70 db [2] 6b 95 [2] 56 }

  condition:
    any of them
}