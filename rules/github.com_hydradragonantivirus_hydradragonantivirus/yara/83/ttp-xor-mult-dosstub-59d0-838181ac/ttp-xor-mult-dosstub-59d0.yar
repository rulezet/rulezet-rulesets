rule TTP_XOR_MULT_DOSStub_59d0 {
  strings:
    $key_59d0 = { 0d b8 [2] 79 a0 [2] 3e a2 [2] 79 b3 [2] 37 bf [2] 3b b5 [2] 2c be [2] 37 f0 [2] 0a }

  condition:
    any of them
}