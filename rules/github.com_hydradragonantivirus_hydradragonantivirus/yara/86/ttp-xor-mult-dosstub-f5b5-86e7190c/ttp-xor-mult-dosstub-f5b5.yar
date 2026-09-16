rule TTP_XOR_MULT_DOSStub_f5b5 {
  strings:
    $key_f5b5 = { a1 dd [2] d5 c5 [2] 92 c7 [2] d5 d6 [2] 9b da [2] 97 d0 [2] 80 db [2] 9b 95 [2] a6 }

  condition:
    any of them
}