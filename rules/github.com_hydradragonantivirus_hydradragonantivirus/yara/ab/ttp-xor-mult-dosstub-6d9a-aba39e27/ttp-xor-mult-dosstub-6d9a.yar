rule TTP_XOR_MULT_DOSStub_6d9a {
  strings:
    $key_6d9a = { 39 f2 [2] 4d ea [2] 0a e8 [2] 4d f9 [2] 03 f5 [2] 0f ff [2] 18 f4 [2] 03 ba [2] 3e }

  condition:
    any of them
}