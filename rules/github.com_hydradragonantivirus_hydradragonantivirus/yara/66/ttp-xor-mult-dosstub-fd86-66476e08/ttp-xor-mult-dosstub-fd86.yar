rule TTP_XOR_MULT_DOSStub_fd86 {
  strings:
    $key_fd86 = { a9 ee [2] dd f6 [2] 9a f4 [2] dd e5 [2] 93 e9 [2] 9f e3 [2] 88 e8 [2] 93 a6 [2] ae }

  condition:
    any of them
}