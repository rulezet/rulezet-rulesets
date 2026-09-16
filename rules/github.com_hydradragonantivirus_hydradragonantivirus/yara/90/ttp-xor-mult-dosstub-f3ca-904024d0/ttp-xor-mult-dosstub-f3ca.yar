rule TTP_XOR_MULT_DOSStub_f3ca {
  strings:
    $key_f3ca = { a7 a2 [2] d3 ba [2] 94 b8 [2] d3 a9 [2] 9d a5 [2] 91 af [2] 86 a4 [2] 9d ea [2] a0 }

  condition:
    any of them
}