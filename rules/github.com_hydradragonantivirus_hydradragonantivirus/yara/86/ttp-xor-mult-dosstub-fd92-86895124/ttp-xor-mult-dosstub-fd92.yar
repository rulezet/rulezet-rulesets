rule TTP_XOR_MULT_DOSStub_fd92 {
  strings:
    $key_fd92 = { a9 fa [2] dd e2 [2] 9a e0 [2] dd f1 [2] 93 fd [2] 9f f7 [2] 88 fc [2] 93 b2 [2] ae }

  condition:
    any of them
}