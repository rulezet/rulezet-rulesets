rule TTP_XOR_MULT_DOSStub_ec91 {
  strings:
    $key_ec91 = { b8 f9 [2] cc e1 [2] 8b e3 [2] cc f2 [2] 82 fe [2] 8e f4 [2] 99 ff [2] 82 b1 [2] bf }

  condition:
    any of them
}