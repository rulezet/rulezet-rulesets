rule TTP_XOR_MULT_DOSStub_fd0d {
  strings:
    $key_fd0d = { a9 65 [2] dd 7d [2] 9a 7f [2] dd 6e [2] 93 62 [2] 9f 68 [2] 88 63 [2] 93 2d [2] ae }

  condition:
    any of them
}