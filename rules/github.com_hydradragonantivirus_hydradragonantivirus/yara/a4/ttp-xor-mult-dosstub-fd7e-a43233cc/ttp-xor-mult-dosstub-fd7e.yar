rule TTP_XOR_MULT_DOSStub_fd7e {
  strings:
    $key_fd7e = { a9 16 [2] dd 0e [2] 9a 0c [2] dd 1d [2] 93 11 [2] 9f 1b [2] 88 10 [2] 93 5e [2] ae }

  condition:
    any of them
}