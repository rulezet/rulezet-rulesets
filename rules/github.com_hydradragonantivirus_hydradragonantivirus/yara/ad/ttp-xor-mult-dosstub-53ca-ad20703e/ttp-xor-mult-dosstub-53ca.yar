rule TTP_XOR_MULT_DOSStub_53ca {
  strings:
    $key_53ca = { 07 a2 [2] 73 ba [2] 34 b8 [2] 73 a9 [2] 3d a5 [2] 31 af [2] 26 a4 [2] 3d ea [2] 00 }

  condition:
    any of them
}