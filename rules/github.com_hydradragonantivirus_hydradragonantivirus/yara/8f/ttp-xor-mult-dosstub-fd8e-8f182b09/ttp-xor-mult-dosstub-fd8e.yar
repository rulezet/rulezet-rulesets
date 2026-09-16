rule TTP_XOR_MULT_DOSStub_fd8e {
  strings:
    $key_fd8e = { a9 e6 [2] dd fe [2] 9a fc [2] dd ed [2] 93 e1 [2] 9f eb [2] 88 e0 [2] 93 ae [2] ae }

  condition:
    any of them
}