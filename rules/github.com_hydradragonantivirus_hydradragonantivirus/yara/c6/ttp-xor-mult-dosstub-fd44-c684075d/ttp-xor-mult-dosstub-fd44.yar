rule TTP_XOR_MULT_DOSStub_fd44 {
  strings:
    $key_fd44 = { a9 2c [2] dd 34 [2] 9a 36 [2] dd 27 [2] 93 2b [2] 9f 21 [2] 88 2a [2] 93 64 [2] ae }

  condition:
    any of them
}