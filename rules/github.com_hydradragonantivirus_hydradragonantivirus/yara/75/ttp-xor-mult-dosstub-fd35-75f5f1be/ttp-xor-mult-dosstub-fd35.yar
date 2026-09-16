rule TTP_XOR_MULT_DOSStub_fd35 {
  strings:
    $key_fd35 = { a9 5d [2] dd 45 [2] 9a 47 [2] dd 56 [2] 93 5a [2] 9f 50 [2] 88 5b [2] 93 15 [2] ae }

  condition:
    any of them
}