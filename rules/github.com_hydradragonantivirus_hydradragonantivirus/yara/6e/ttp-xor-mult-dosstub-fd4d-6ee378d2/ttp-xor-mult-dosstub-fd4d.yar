rule TTP_XOR_MULT_DOSStub_fd4d {
  strings:
    $key_fd4d = { a9 25 [2] dd 3d [2] 9a 3f [2] dd 2e [2] 93 22 [2] 9f 28 [2] 88 23 [2] 93 6d [2] ae }

  condition:
    any of them
}