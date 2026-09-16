rule TTP_XOR_MULT_DOSStub_fd51 {
  strings:
    $key_fd51 = { a9 39 [2] dd 21 [2] 9a 23 [2] dd 32 [2] 93 3e [2] 9f 34 [2] 88 3f [2] 93 71 [2] ae }

  condition:
    any of them
}