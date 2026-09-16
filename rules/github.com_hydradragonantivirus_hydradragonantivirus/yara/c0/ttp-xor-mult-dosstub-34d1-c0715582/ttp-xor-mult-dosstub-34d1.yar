rule TTP_XOR_MULT_DOSStub_34d1 {
  strings:
    $key_34d1 = { 60 b9 [2] 14 a1 [2] 53 a3 [2] 14 b2 [2] 5a be [2] 56 b4 [2] 41 bf [2] 5a f1 [2] 67 }

  condition:
    any of them
}