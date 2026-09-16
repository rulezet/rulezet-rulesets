rule TTP_XOR_MULT_DOSStub_4d9a {
  strings:
    $key_4d9a = { 19 f2 [2] 6d ea [2] 2a e8 [2] 6d f9 [2] 23 f5 [2] 2f ff [2] 38 f4 [2] 23 ba [2] 1e }

  condition:
    any of them
}