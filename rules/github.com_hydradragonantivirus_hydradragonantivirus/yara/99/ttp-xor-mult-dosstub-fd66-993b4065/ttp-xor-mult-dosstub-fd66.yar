rule TTP_XOR_MULT_DOSStub_fd66 {
  strings:
    $key_fd66 = { a9 0e [2] dd 16 [2] 9a 14 [2] dd 05 [2] 93 09 [2] 9f 03 [2] 88 08 [2] 93 46 [2] ae }

  condition:
    any of them
}