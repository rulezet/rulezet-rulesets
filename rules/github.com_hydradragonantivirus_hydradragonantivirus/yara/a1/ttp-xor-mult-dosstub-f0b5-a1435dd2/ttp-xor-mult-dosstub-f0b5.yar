rule TTP_XOR_MULT_DOSStub_f0b5 {
  strings:
    $key_f0b5 = { a4 dd [2] d0 c5 [2] 97 c7 [2] d0 d6 [2] 9e da [2] 92 d0 [2] 85 db [2] 9e 95 [2] a3 }

  condition:
    any of them
}