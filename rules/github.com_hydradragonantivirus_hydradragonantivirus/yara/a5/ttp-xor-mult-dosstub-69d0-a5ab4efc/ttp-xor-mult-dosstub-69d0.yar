rule TTP_XOR_MULT_DOSStub_69d0 {
  strings:
    $key_69d0 = { 3d b8 [2] 49 a0 [2] 0e a2 [2] 49 b3 [2] 07 bf [2] 0b b5 [2] 1c be [2] 07 f0 [2] 3a }

  condition:
    any of them
}