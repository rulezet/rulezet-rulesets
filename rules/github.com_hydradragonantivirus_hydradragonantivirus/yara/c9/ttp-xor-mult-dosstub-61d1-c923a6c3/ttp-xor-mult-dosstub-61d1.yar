rule TTP_XOR_MULT_DOSStub_61d1 {
  strings:
    $key_61d1 = { 35 b9 [2] 41 a1 [2] 06 a3 [2] 41 b2 [2] 0f be [2] 03 b4 [2] 14 bf [2] 0f f1 [2] 32 }

  condition:
    any of them
}