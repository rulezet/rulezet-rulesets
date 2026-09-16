rule TTP_XOR_MULT_DOSStub_fd47 {
  strings:
    $key_fd47 = { a9 2f [2] dd 37 [2] 9a 35 [2] dd 24 [2] 93 28 [2] 9f 22 [2] 88 29 [2] 93 67 [2] ae }

  condition:
    any of them
}