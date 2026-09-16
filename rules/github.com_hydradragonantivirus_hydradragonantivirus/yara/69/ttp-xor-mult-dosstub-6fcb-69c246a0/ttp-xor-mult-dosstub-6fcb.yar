rule TTP_XOR_MULT_DOSStub_6fcb {
  strings:
    $key_6fcb = { 3b a3 [2] 4f bb [2] 08 b9 [2] 4f a8 [2] 01 a4 [2] 0d ae [2] 1a a5 [2] 01 eb [2] 3c }

  condition:
    any of them
}