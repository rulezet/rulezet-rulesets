rule TTP_XOR_MULT_DOSStub_fd4a {
  strings:
    $key_fd4a = { a9 22 [2] dd 3a [2] 9a 38 [2] dd 29 [2] 93 25 [2] 9f 2f [2] 88 24 [2] 93 6a [2] ae }

  condition:
    any of them
}