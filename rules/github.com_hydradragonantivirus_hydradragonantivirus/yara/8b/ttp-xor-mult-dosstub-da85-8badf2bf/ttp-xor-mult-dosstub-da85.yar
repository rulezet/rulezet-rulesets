rule TTP_XOR_MULT_DOSStub_da85 {
  strings:
    $key_da85 = { 8e ed [2] fa f5 [2] bd f7 [2] fa e6 [2] b4 ea [2] b8 e0 [2] af eb [2] b4 a5 [2] 89 }

  condition:
    any of them
}