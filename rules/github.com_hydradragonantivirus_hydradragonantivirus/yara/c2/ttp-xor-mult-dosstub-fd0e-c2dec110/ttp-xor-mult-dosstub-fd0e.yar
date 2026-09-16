rule TTP_XOR_MULT_DOSStub_fd0e {
  strings:
    $key_fd0e = { a9 66 [2] dd 7e [2] 9a 7c [2] dd 6d [2] 93 61 [2] 9f 6b [2] 88 60 [2] 93 2e [2] ae }

  condition:
    any of them
}