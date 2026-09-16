rule TTP_XOR_MULT_DOSStub_79d0 {
  strings:
    $key_79d0 = { 2d b8 [2] 59 a0 [2] 1e a2 [2] 59 b3 [2] 17 bf [2] 1b b5 [2] 0c be [2] 17 f0 [2] 2a }

  condition:
    any of them
}