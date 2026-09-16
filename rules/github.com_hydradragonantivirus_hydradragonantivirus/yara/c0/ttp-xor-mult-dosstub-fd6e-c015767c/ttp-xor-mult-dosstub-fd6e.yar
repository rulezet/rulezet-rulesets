rule TTP_XOR_MULT_DOSStub_fd6e {
  strings:
    $key_fd6e = { a9 06 [2] dd 1e [2] 9a 1c [2] dd 0d [2] 93 01 [2] 9f 0b [2] 88 00 [2] 93 4e [2] ae }

  condition:
    any of them
}