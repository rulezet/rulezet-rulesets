rule TTP_XOR_MULT_DOSStub_fd0c {
  strings:
    $key_fd0c = { a9 64 [2] dd 7c [2] 9a 7e [2] dd 6f [2] 93 63 [2] 9f 69 [2] 88 62 [2] 93 2c [2] ae }

  condition:
    any of them
}