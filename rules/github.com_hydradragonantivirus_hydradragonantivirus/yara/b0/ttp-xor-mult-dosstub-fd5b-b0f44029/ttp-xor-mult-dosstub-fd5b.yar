rule TTP_XOR_MULT_DOSStub_fd5b {
  strings:
    $key_fd5b = { a9 33 [2] dd 2b [2] 9a 29 [2] dd 38 [2] 93 34 [2] 9f 3e [2] 88 35 [2] 93 7b [2] ae }

  condition:
    any of them
}