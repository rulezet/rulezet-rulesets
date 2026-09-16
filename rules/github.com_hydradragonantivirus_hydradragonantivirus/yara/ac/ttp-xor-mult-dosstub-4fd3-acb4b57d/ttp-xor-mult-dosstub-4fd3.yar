rule TTP_XOR_MULT_DOSStub_4fd3 {
  strings:
    $key_4fd3 = { 1b bb [2] 6f a3 [2] 28 a1 [2] 6f b0 [2] 21 bc [2] 2d b6 [2] 3a bd [2] 21 f3 [2] 1c }

  condition:
    any of them
}