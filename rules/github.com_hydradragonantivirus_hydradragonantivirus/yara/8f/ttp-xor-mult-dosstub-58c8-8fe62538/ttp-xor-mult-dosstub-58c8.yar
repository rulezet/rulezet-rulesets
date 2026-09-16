rule TTP_XOR_MULT_DOSStub_58c8 {
  strings:
    $key_58c8 = { 0c a0 [2] 78 b8 [2] 3f ba [2] 78 ab [2] 36 a7 [2] 3a ad [2] 2d a6 [2] 36 e8 [2] 0b }

  condition:
    any of them
}