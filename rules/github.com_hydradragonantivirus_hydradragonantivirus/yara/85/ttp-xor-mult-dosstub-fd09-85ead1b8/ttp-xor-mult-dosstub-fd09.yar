rule TTP_XOR_MULT_DOSStub_fd09 {
  strings:
    $key_fd09 = { a9 61 [2] dd 79 [2] 9a 7b [2] dd 6a [2] 93 66 [2] 9f 6c [2] 88 67 [2] 93 29 [2] ae }

  condition:
    any of them
}