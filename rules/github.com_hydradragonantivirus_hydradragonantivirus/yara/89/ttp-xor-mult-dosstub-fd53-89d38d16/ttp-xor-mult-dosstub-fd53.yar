rule TTP_XOR_MULT_DOSStub_fd53 {
  strings:
    $key_fd53 = { a9 3b [2] dd 23 [2] 9a 21 [2] dd 30 [2] 93 3c [2] 9f 36 [2] 88 3d [2] 93 73 [2] ae }

  condition:
    any of them
}