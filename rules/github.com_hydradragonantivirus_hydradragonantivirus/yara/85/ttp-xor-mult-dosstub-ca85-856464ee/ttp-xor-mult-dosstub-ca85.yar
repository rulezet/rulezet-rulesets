rule TTP_XOR_MULT_DOSStub_ca85 {
  strings:
    $key_ca85 = { 9e ed [2] ea f5 [2] ad f7 [2] ea e6 [2] a4 ea [2] a8 e0 [2] bf eb [2] a4 a5 [2] 99 }

  condition:
    any of them
}