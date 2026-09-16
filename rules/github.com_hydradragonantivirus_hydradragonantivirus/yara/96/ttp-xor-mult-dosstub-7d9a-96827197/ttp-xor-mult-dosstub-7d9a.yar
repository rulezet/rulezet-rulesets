rule TTP_XOR_MULT_DOSStub_7d9a {
  strings:
    $key_7d9a = { 29 f2 [2] 5d ea [2] 1a e8 [2] 5d f9 [2] 13 f5 [2] 1f ff [2] 08 f4 [2] 13 ba [2] 2e }

  condition:
    any of them
}