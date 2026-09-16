rule TTP_XOR_MULT_DOSStub_fd9b {
  strings:
    $key_fd9b = { a9 f3 [2] dd eb [2] 9a e9 [2] dd f8 [2] 93 f4 [2] 9f fe [2] 88 f5 [2] 93 bb [2] ae }

  condition:
    any of them
}