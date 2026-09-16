rule TTP_XOR_MULT_DOSStub_fd71 {
  strings:
    $key_fd71 = { a9 19 [2] dd 01 [2] 9a 03 [2] dd 12 [2] 93 1e [2] 9f 14 [2] 88 1f [2] 93 51 [2] ae }

  condition:
    any of them
}