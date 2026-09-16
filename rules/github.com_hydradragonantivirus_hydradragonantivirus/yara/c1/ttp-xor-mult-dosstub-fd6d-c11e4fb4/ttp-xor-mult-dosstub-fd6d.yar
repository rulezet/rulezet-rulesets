rule TTP_XOR_MULT_DOSStub_fd6d {
  strings:
    $key_fd6d = { a9 05 [2] dd 1d [2] 9a 1f [2] dd 0e [2] 93 02 [2] 9f 08 [2] 88 03 [2] 93 4d [2] ae }

  condition:
    any of them
}