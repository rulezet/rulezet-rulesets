rule TTP_XOR_MULT_DOSStub_b99a {
  strings:
    $key_b99a = { ed f2 [2] 99 ea [2] de e8 [2] 99 f9 [2] d7 f5 [2] db ff [2] cc f4 [2] d7 ba [2] ea }

  condition:
    any of them
}