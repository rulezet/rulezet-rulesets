rule TTP_XOR_MULT_DOSStub_fd45 {
  strings:
    $key_fd45 = { a9 2d [2] dd 35 [2] 9a 37 [2] dd 26 [2] 93 2a [2] 9f 20 [2] 88 2b [2] 93 65 [2] ae }

  condition:
    any of them
}