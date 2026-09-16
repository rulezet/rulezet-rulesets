rule TTP_XOR_MULT_DOSStub_f19a {
  strings:
    $key_f19a = { a5 f2 [2] d1 ea [2] 96 e8 [2] d1 f9 [2] 9f f5 [2] 93 ff [2] 84 f4 [2] 9f ba [2] a2 }

  condition:
    any of them
}