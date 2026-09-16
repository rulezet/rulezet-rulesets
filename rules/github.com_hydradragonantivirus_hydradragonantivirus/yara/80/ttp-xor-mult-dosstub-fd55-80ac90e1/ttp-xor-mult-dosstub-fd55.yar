rule TTP_XOR_MULT_DOSStub_fd55 {
  strings:
    $key_fd55 = { a9 3d [2] dd 25 [2] 9a 27 [2] dd 36 [2] 93 3a [2] 9f 30 [2] 88 3b [2] 93 75 [2] ae }

  condition:
    any of them
}