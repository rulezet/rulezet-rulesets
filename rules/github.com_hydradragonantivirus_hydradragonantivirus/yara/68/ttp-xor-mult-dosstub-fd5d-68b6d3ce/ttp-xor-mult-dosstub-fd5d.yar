rule TTP_XOR_MULT_DOSStub_fd5d {
  strings:
    $key_fd5d = { a9 35 [2] dd 2d [2] 9a 2f [2] dd 3e [2] 93 32 [2] 9f 38 [2] 88 33 [2] 93 7d [2] ae }

  condition:
    any of them
}