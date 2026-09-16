rule TTP_XOR_MULT_DOSStub_43ca {
  strings:
    $key_43ca = { 17 a2 [2] 63 ba [2] 24 b8 [2] 63 a9 [2] 2d a5 [2] 21 af [2] 36 a4 [2] 2d ea [2] 10 }

  condition:
    any of them
}