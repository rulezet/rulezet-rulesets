rule TTP_XOR_MULT_DOSStub_15d1 {
  strings:
    $key_15d1 = { 41 b9 [2] 35 a1 [2] 72 a3 [2] 35 b2 [2] 7b be [2] 77 b4 [2] 60 bf [2] 7b f1 [2] 46 }

  condition:
    any of them
}