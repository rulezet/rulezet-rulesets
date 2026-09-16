rule TTP_XOR_MULT_DOSStub_da83 {
  strings:
    $key_da83 = { 8e eb [2] fa f3 [2] bd f1 [2] fa e0 [2] b4 ec [2] b8 e6 [2] af ed [2] b4 a3 [2] 89 }

  condition:
    any of them
}