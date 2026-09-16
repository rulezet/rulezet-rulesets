rule TTP_XOR_MULT_DOSStub_b991 {
  strings:
    $key_b991 = { ed f9 [2] 99 e1 [2] de e3 [2] 99 f2 [2] d7 fe [2] db f4 [2] cc ff [2] d7 b1 [2] ea }

  condition:
    any of them
}