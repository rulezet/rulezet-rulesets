rule TTP_XOR_MULT_DOSStub_3b9a {
  strings:
    $key_3b9a = { 6f f2 [2] 1b ea [2] 5c e8 [2] 1b f9 [2] 55 f5 [2] 59 ff [2] 4e f4 [2] 55 ba [2] 68 }

  condition:
    any of them
}