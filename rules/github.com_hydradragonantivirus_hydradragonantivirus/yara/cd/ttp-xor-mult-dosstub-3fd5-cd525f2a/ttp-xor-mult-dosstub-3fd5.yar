rule TTP_XOR_MULT_DOSStub_3fd5 {
  strings:
    $key_3fd5 = { 6b bd [2] 1f a5 [2] 58 a7 [2] 1f b6 [2] 51 ba [2] 5d b0 [2] 4a bb [2] 51 f5 [2] 6c }

  condition:
    any of them
}