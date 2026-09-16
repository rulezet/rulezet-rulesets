rule TTP_XOR_MULT_DOSStub_4b9a {
  strings:
    $key_4b9a = { 1f f2 [2] 6b ea [2] 2c e8 [2] 6b f9 [2] 25 f5 [2] 29 ff [2] 3e f4 [2] 25 ba [2] 18 }

  condition:
    any of them
}