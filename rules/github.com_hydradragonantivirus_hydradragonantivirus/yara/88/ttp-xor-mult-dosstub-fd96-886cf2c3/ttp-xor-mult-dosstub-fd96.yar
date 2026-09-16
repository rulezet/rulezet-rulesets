rule TTP_XOR_MULT_DOSStub_fd96 {
  strings:
    $key_fd96 = { a9 fe [2] dd e6 [2] 9a e4 [2] dd f5 [2] 93 f9 [2] 9f f3 [2] 88 f8 [2] 93 b6 [2] ae }

  condition:
    any of them
}