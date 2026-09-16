rule TTP_XOR_MULT_DOSStub_fd7f {
  strings:
    $key_fd7f = { a9 17 [2] dd 0f [2] 9a 0d [2] dd 1c [2] 93 10 [2] 9f 1a [2] 88 11 [2] 93 5f [2] ae }

  condition:
    any of them
}