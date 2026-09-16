rule TTP_XOR_MULT_DOSStub_fd1b {
  strings:
    $key_fd1b = { a9 73 [2] dd 6b [2] 9a 69 [2] dd 78 [2] 93 74 [2] 9f 7e [2] 88 75 [2] 93 3b [2] ae }

  condition:
    any of them
}