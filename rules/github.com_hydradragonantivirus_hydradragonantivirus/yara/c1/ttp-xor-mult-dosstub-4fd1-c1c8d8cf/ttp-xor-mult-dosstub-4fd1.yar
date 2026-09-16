rule TTP_XOR_MULT_DOSStub_4fd1 {
  strings:
    $key_4fd1 = { 1b b9 [2] 6f a1 [2] 28 a3 [2] 6f b2 [2] 21 be [2] 2d b4 [2] 3a bf [2] 21 f1 [2] 1c }

  condition:
    any of them
}