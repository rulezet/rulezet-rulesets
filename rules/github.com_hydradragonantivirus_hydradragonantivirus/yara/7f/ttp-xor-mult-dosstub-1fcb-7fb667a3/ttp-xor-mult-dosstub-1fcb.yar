rule TTP_XOR_MULT_DOSStub_1fcb {
  strings:
    $key_1fcb = { 4b a3 [2] 3f bb [2] 78 b9 [2] 3f a8 [2] 71 a4 [2] 7d ae [2] 6a a5 [2] 71 eb [2] 4c }

  condition:
    any of them
}