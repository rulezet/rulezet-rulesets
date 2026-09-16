rule TTP_XOR_MULT_DOSStub_4fd2 {
  strings:
    $key_4fd2 = { 1b ba [2] 6f a2 [2] 28 a0 [2] 6f b1 [2] 21 bd [2] 2d b7 [2] 3a bc [2] 21 f2 [2] 1c }

  condition:
    any of them
}