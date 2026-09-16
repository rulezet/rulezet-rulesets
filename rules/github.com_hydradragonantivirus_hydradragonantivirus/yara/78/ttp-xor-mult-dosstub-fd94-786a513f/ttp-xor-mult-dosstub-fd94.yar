rule TTP_XOR_MULT_DOSStub_fd94 {
  strings:
    $key_fd94 = { a9 fc [2] dd e4 [2] 9a e6 [2] dd f7 [2] 93 fb [2] 9f f1 [2] 88 fa [2] 93 b4 [2] ae }

  condition:
    any of them
}