rule TTP_XOR_MULT_DOSStub_6fd3 {
  strings:
    $key_6fd3 = { 3b bb [2] 4f a3 [2] 08 a1 [2] 4f b0 [2] 01 bc [2] 0d b6 [2] 1a bd [2] 01 f3 [2] 3c }

  condition:
    any of them
}