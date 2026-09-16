rule TTP_XOR_MULT_DOSStub_fd1f {
  strings:
    $key_fd1f = { a9 77 [2] dd 6f [2] 9a 6d [2] dd 7c [2] 93 70 [2] 9f 7a [2] 88 71 [2] 93 3f [2] ae }

  condition:
    any of them
}