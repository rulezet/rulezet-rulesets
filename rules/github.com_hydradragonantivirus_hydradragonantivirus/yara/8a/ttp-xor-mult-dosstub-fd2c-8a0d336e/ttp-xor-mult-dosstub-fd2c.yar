rule TTP_XOR_MULT_DOSStub_fd2c {
  strings:
    $key_fd2c = { a9 44 [2] dd 5c [2] 9a 5e [2] dd 4f [2] 93 43 [2] 9f 49 [2] 88 42 [2] 93 0c [2] ae }

  condition:
    any of them
}