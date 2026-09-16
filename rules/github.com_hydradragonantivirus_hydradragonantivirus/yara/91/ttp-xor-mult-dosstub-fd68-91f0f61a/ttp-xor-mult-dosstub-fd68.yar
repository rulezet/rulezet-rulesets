rule TTP_XOR_MULT_DOSStub_fd68 {
  strings:
    $key_fd68 = { a9 00 [2] dd 18 [2] 9a 1a [2] dd 0b [2] 93 07 [2] 9f 0d [2] 88 06 [2] 93 48 [2] ae }

  condition:
    any of them
}