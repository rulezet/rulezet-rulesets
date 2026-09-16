rule TTP_XOR_MULT_DOSStub_fd79 {
  strings:
    $key_fd79 = { a9 11 [2] dd 09 [2] 9a 0b [2] dd 1a [2] 93 16 [2] 9f 1c [2] 88 17 [2] 93 59 [2] ae }

  condition:
    any of them
}