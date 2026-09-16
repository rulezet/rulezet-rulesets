rule TTP_XOR_MULT_DOSStub_1b9a {
  strings:
    $key_1b9a = { 4f f2 [2] 3b ea [2] 7c e8 [2] 3b f9 [2] 75 f5 [2] 79 ff [2] 6e f4 [2] 75 ba [2] 48 }

  condition:
    any of them
}