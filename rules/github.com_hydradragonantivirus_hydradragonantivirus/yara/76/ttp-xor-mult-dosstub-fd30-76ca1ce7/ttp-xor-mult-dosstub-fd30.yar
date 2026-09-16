rule TTP_XOR_MULT_DOSStub_fd30 {
  strings:
    $key_fd30 = { a9 58 [2] dd 40 [2] 9a 42 [2] dd 53 [2] 93 5f [2] 9f 55 [2] 88 5e [2] 93 10 [2] ae }

  condition:
    any of them
}