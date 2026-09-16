rule TTP_XOR_MULT_DOSStub_fd03 {
  strings:
    $key_fd03 = { a9 6b [2] dd 73 [2] 9a 71 [2] dd 60 [2] 93 6c [2] 9f 66 [2] 88 6d [2] 93 23 [2] ae }

  condition:
    any of them
}