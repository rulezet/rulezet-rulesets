rule TTP_XOR_MULT_DOSStub_fd0f {
  strings:
    $key_fd0f = { a9 67 [2] dd 7f [2] 9a 7d [2] dd 6c [2] 93 60 [2] 9f 6a [2] 88 61 [2] 93 2f [2] ae }

  condition:
    any of them
}