rule TTP_XOR_MULT_DOSStub_fd36 {
  strings:
    $key_fd36 = { a9 5e [2] dd 46 [2] 9a 44 [2] dd 55 [2] 93 59 [2] 9f 53 [2] 88 58 [2] 93 16 [2] ae }

  condition:
    any of them
}