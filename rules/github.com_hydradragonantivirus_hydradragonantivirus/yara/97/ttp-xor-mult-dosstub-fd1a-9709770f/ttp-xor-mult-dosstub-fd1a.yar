rule TTP_XOR_MULT_DOSStub_fd1a {
  strings:
    $key_fd1a = { a9 72 [2] dd 6a [2] 9a 68 [2] dd 79 [2] 93 75 [2] 9f 7f [2] 88 74 [2] 93 3a [2] ae }

  condition:
    any of them
}