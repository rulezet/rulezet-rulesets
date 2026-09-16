rule TTP_XOR_MULT_DOSStub_4fcb {
  strings:
    $key_4fcb = { 1b a3 [2] 6f bb [2] 28 b9 [2] 6f a8 [2] 21 a4 [2] 2d ae [2] 3a a5 [2] 21 eb [2] 1c }

  condition:
    any of them
}