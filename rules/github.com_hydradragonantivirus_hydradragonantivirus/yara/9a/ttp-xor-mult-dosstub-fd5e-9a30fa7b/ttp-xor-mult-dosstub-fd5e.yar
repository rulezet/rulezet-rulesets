rule TTP_XOR_MULT_DOSStub_fd5e {
  strings:
    $key_fd5e = { a9 36 [2] dd 2e [2] 9a 2c [2] dd 3d [2] 93 31 [2] 9f 3b [2] 88 30 [2] 93 7e [2] ae }

  condition:
    any of them
}