rule TTP_XOR_MULT_DOSStub_6fd5 {
  strings:
    $key_6fd5 = { 3b bd [2] 4f a5 [2] 08 a7 [2] 4f b6 [2] 01 ba [2] 0d b0 [2] 1a bb [2] 01 f5 [2] 3c }

  condition:
    any of them
}