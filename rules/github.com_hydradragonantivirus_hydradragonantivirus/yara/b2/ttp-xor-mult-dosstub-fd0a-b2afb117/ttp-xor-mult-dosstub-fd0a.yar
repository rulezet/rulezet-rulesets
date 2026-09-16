rule TTP_XOR_MULT_DOSStub_fd0a {
  strings:
    $key_fd0a = { a9 62 [2] dd 7a [2] 9a 78 [2] dd 69 [2] 93 65 [2] 9f 6f [2] 88 64 [2] 93 2a [2] ae }

  condition:
    any of them
}