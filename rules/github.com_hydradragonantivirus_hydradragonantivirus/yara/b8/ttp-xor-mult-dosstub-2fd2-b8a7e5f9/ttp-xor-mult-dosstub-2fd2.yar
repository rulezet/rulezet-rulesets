rule TTP_XOR_MULT_DOSStub_2fd2 {
  strings:
    $key_2fd2 = { 7b ba [2] 0f a2 [2] 48 a0 [2] 0f b1 [2] 41 bd [2] 4d b7 [2] 5a bc [2] 41 f2 [2] 7c }

  condition:
    any of them
}