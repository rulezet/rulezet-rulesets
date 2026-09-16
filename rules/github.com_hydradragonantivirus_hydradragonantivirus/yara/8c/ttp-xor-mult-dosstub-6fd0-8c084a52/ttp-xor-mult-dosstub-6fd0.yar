rule TTP_XOR_MULT_DOSStub_6fd0 {
  strings:
    $key_6fd0 = { 3b b8 [2] 4f a0 [2] 08 a2 [2] 4f b3 [2] 01 bf [2] 0d b5 [2] 1a be [2] 01 f0 [2] 3c }

  condition:
    any of them
}