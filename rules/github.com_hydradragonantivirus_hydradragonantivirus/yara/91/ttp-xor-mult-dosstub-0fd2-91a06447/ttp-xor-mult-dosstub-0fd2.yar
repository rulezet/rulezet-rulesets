rule TTP_XOR_MULT_DOSStub_0fd2 {
  strings:
    $key_0fd2 = { 5b ba [2] 2f a2 [2] 68 a0 [2] 2f b1 [2] 61 bd [2] 6d b7 [2] 7a bc [2] 61 f2 [2] 5c }

  condition:
    any of them
}