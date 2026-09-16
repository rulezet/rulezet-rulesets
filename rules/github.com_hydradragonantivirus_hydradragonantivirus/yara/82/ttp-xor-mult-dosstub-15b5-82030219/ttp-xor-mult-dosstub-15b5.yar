rule TTP_XOR_MULT_DOSStub_15b5 {
  strings:
    $key_15b5 = { 41 dd [2] 35 c5 [2] 72 c7 [2] 35 d6 [2] 7b da [2] 77 d0 [2] 60 db [2] 7b 95 [2] 46 }

  condition:
    any of them
}