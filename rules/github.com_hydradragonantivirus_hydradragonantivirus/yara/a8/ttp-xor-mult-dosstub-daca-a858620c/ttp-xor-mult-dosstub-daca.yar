rule TTP_XOR_MULT_DOSStub_daca {
  strings:
    $key_daca = { 8e a2 [2] fa ba [2] bd b8 [2] fa a9 [2] b4 a5 [2] b8 af [2] af a4 [2] b4 ea [2] 89 }

  condition:
    any of them
}