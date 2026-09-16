rule TTP_XOR_MULT_DOSStub_da80 {
  strings:
    $key_da80 = { 8e e8 [2] fa f0 [2] bd f2 [2] fa e3 [2] b4 ef [2] b8 e5 [2] af ee [2] b4 a0 [2] 89 }

  condition:
    any of them
}