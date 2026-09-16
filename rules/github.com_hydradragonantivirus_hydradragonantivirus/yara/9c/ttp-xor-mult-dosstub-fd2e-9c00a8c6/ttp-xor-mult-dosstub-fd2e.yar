rule TTP_XOR_MULT_DOSStub_fd2e {
  strings:
    $key_fd2e = { a9 46 [2] dd 5e [2] 9a 5c [2] dd 4d [2] 93 41 [2] 9f 4b [2] 88 40 [2] 93 0e [2] ae }

  condition:
    any of them
}