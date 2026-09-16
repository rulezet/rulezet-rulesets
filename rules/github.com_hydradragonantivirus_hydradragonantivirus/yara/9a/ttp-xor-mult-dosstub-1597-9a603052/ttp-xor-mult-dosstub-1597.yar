rule TTP_XOR_MULT_DOSStub_1597 {
  strings:
    $key_1597 = { 41 ff [2] 35 e7 [2] 72 e5 [2] 35 f4 [2] 7b f8 [2] 77 f2 [2] 60 f9 [2] 7b b7 [2] 46 }

  condition:
    any of them
}