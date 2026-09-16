rule TTP_XOR_MULT_DOSStub_4497 {
  strings:
    $key_4497 = { 10 ff [2] 64 e7 [2] 23 e5 [2] 64 f4 [2] 2a f8 [2] 26 f2 [2] 31 f9 [2] 2a b7 [2] 17 }

  condition:
    any of them
}