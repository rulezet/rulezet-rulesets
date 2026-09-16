rule TTP_XOR_MULT_DOSStub_fd97 {
  strings:
    $key_fd97 = { a9 ff [2] dd e7 [2] 9a e5 [2] dd f4 [2] 93 f8 [2] 9f f2 [2] 88 f9 [2] 93 b7 [2] ae }

  condition:
    any of them
}