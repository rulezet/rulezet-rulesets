rule TTP_XOR_MULT_DOSStub_36d0 {
  strings:
    $key_36d0 = { 62 b8 [2] 16 a0 [2] 51 a2 [2] 16 b3 [2] 58 bf [2] 54 b5 [2] 43 be [2] 58 f0 [2] 65 }

  condition:
    any of them
}