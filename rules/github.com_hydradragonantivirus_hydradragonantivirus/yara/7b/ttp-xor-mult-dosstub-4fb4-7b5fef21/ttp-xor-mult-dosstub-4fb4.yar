rule TTP_XOR_MULT_DOSStub_4fb4 {
  strings:
    $key_4fb4 = { 1b dc [2] 6f c4 [2] 28 c6 [2] 6f d7 [2] 21 db [2] 2d d1 [2] 3a da [2] 21 94 [2] 1c }

  condition:
    any of them
}