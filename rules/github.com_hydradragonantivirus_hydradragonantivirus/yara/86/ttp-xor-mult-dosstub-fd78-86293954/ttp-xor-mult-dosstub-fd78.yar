rule TTP_XOR_MULT_DOSStub_fd78 {
  strings:
    $key_fd78 = { a9 10 [2] dd 08 [2] 9a 0a [2] dd 1b [2] 93 17 [2] 9f 1d [2] 88 16 [2] 93 58 [2] ae }

  condition:
    any of them
}