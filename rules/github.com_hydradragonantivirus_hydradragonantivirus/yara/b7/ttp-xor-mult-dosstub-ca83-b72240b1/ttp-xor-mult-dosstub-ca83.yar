rule TTP_XOR_MULT_DOSStub_ca83 {
  strings:
    $key_ca83 = { 9e eb [2] ea f3 [2] ad f1 [2] ea e0 [2] a4 ec [2] a8 e6 [2] bf ed [2] a4 a3 [2] 99 }

  condition:
    any of them
}