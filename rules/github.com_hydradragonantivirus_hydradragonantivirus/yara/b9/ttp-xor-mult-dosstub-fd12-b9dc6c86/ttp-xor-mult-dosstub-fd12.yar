rule TTP_XOR_MULT_DOSStub_fd12 {
  strings:
    $key_fd12 = { a9 7a [2] dd 62 [2] 9a 60 [2] dd 71 [2] 93 7d [2] 9f 77 [2] 88 7c [2] 93 32 [2] ae }

  condition:
    any of them
}