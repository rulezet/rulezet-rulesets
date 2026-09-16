rule TTP_XOR_MULT_DOSStub_fd00 {
  strings:
    $key_fd00 = { a9 68 [2] dd 70 [2] 9a 72 [2] dd 63 [2] 93 6f [2] 9f 65 [2] 88 6e [2] 93 20 [2] ae }

  condition:
    any of them
}