rule TTP_XOR_MULT_DOSStub_5d9a {
  strings:
    $key_5d9a = { 09 f2 [2] 7d ea [2] 3a e8 [2] 7d f9 [2] 33 f5 [2] 3f ff [2] 28 f4 [2] 33 ba [2] 0e }

  condition:
    any of them
}