rule TTP_XOR_MULT_DOSStub_fd41 {
  strings:
    $key_fd41 = { a9 29 [2] dd 31 [2] 9a 33 [2] dd 22 [2] 93 2e [2] 9f 24 [2] 88 2f [2] 93 61 [2] ae }

  condition:
    any of them
}