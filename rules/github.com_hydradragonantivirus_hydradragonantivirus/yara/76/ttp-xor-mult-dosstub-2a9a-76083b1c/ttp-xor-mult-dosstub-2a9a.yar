rule TTP_XOR_MULT_DOSStub_2a9a {
  strings:
    $key_2a9a = { 7e f2 [2] 0a ea [2] 4d e8 [2] 0a f9 [2] 44 f5 [2] 48 ff [2] 5f f4 [2] 44 ba [2] 79 }

  condition:
    any of them
}