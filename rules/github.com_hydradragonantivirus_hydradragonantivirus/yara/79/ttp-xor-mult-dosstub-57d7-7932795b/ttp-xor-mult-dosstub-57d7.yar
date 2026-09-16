rule TTP_XOR_MULT_DOSStub_57d7 {
  strings:
    $key_57d7 = { 03 bf [2] 77 a7 [2] 30 a5 [2] 77 b4 [2] 39 b8 [2] 35 b2 [2] 22 b9 [2] 39 f7 [2] 04 }

  condition:
    any of them
}