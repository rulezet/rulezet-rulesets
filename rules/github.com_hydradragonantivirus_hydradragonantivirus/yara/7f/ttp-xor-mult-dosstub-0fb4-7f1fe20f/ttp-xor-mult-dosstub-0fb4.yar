rule TTP_XOR_MULT_DOSStub_0fb4 {
  strings:
    $key_0fb4 = { 5b dc [2] 2f c4 [2] 68 c6 [2] 2f d7 [2] 61 db [2] 6d d1 [2] 7a da [2] 61 94 [2] 5c }

  condition:
    any of them
}