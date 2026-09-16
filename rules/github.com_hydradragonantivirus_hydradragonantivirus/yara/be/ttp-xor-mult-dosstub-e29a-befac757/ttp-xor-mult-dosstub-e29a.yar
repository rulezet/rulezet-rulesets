rule TTP_XOR_MULT_DOSStub_e29a {
  strings:
    $key_e29a = { b6 f2 [2] c2 ea [2] 85 e8 [2] c2 f9 [2] 8c f5 [2] 80 ff [2] 97 f4 [2] 8c ba [2] b1 }

  condition:
    any of them
}