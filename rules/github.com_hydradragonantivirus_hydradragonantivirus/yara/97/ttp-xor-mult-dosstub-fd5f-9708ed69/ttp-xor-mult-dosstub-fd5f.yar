rule TTP_XOR_MULT_DOSStub_fd5f {
  strings:
    $key_fd5f = { a9 37 [2] dd 2f [2] 9a 2d [2] dd 3c [2] 93 30 [2] 9f 3a [2] 88 31 [2] 93 7f [2] ae }

  condition:
    any of them
}