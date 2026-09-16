rule TTP_XOR_MULT_DOSStub_ca27 {
  strings:
    $key_ca27 = { 9e 4f [2] ea 57 [2] ad 55 [2] ea 44 [2] a4 48 [2] a8 42 [2] bf 49 [2] a4 07 [2] 99 }

  condition:
    any of them
}