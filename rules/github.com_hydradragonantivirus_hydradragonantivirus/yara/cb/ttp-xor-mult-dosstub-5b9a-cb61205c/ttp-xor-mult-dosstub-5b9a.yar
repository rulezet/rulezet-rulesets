rule TTP_XOR_MULT_DOSStub_5b9a {
  strings:
    $key_5b9a = { 0f f2 [2] 7b ea [2] 3c e8 [2] 7b f9 [2] 35 f5 [2] 39 ff [2] 2e f4 [2] 35 ba [2] 08 }

  condition:
    any of them
}