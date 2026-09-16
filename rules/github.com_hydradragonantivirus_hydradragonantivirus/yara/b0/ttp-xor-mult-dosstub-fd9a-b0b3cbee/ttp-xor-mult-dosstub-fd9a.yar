rule TTP_XOR_MULT_DOSStub_fd9a {
  strings:
    $key_fd9a = { a9 f2 [2] dd ea [2] 9a e8 [2] dd f9 [2] 93 f5 [2] 9f ff [2] 88 f4 [2] 93 ba [2] ae }

  condition:
    any of them
}