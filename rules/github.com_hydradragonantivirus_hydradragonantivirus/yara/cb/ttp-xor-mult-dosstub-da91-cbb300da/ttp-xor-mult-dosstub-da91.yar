rule TTP_XOR_MULT_DOSStub_da91 {
  strings:
    $key_da91 = { 8e f9 [2] fa e1 [2] bd e3 [2] fa f2 [2] b4 fe [2] b8 f4 [2] af ff [2] b4 b1 [2] 89 }

  condition:
    any of them
}