rule TTP_XOR_MULT_DOSStub_fd87 {
  strings:
    $key_fd87 = { a9 ef [2] dd f7 [2] 9a f5 [2] dd e4 [2] 93 e8 [2] 9f e2 [2] 88 e9 [2] 93 a7 [2] ae }

  condition:
    any of them
}