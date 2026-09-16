rule TTP_XOR_MULT_DOSStub_21d1 {
  strings:
    $key_21d1 = { 75 b9 [2] 01 a1 [2] 46 a3 [2] 01 b2 [2] 4f be [2] 43 b4 [2] 54 bf [2] 4f f1 [2] 72 }

  condition:
    any of them
}