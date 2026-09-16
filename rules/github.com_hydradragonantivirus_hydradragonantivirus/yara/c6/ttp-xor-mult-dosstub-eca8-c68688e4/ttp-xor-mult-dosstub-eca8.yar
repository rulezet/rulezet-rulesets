rule TTP_XOR_MULT_DOSStub_eca8 {
  strings:
    $key_eca8 = { b8 c0 [2] cc d8 [2] 8b da [2] cc cb [2] 82 c7 [2] 8e cd [2] 99 c6 [2] 82 88 [2] bf }

  condition:
    any of them
}