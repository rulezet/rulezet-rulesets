rule TTP_XOR_MULT_DOSStub_da82 {
  strings:
    $key_da82 = { 8e ea [2] fa f2 [2] bd f0 [2] fa e1 [2] b4 ed [2] b8 e7 [2] af ec [2] b4 a2 [2] 89 }

  condition:
    any of them
}