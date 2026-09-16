rule TTP_XOR_MULT_DOSStub_fd26 {
  strings:
    $key_fd26 = { a9 4e [2] dd 56 [2] 9a 54 [2] dd 45 [2] 93 49 [2] 9f 43 [2] 88 48 [2] 93 06 [2] ae }

  condition:
    any of them
}