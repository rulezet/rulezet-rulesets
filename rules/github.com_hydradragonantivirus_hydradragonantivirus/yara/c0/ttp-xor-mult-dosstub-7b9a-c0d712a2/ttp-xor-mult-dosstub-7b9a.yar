rule TTP_XOR_MULT_DOSStub_7b9a {
  strings:
    $key_7b9a = { 2f f2 [2] 5b ea [2] 1c e8 [2] 5b f9 [2] 15 f5 [2] 19 ff [2] 0e f4 [2] 15 ba [2] 28 }

  condition:
    any of them
}