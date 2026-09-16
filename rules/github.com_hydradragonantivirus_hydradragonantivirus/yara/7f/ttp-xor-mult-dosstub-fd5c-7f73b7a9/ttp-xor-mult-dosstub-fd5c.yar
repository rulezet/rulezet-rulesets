rule TTP_XOR_MULT_DOSStub_fd5c {
  strings:
    $key_fd5c = { a9 34 [2] dd 2c [2] 9a 2e [2] dd 3f [2] 93 33 [2] 9f 39 [2] 88 32 [2] 93 7c [2] ae }

  condition:
    any of them
}