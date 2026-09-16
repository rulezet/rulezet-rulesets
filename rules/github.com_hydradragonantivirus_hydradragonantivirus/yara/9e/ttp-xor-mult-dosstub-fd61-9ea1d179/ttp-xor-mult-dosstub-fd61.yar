rule TTP_XOR_MULT_DOSStub_fd61 {
  strings:
    $key_fd61 = { a9 09 [2] dd 11 [2] 9a 13 [2] dd 02 [2] 93 0e [2] 9f 04 [2] 88 0f [2] 93 41 [2] ae }

  condition:
    any of them
}