rule TTP_XOR_MULT_DOSStub_da81 {
  strings:
    $key_da81 = { 8e e9 [2] fa f1 [2] bd f3 [2] fa e2 [2] b4 ee [2] b8 e4 [2] af ef [2] b4 a1 [2] 89 }

  condition:
    any of them
}