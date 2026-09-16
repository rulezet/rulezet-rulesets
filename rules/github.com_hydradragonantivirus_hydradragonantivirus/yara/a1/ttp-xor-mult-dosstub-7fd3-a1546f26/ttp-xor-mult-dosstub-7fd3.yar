rule TTP_XOR_MULT_DOSStub_7fd3 {
  strings:
    $key_7fd3 = { 2b bb [2] 5f a3 [2] 18 a1 [2] 5f b0 [2] 11 bc [2] 1d b6 [2] 0a bd [2] 11 f3 [2] 2c }

  condition:
    any of them
}