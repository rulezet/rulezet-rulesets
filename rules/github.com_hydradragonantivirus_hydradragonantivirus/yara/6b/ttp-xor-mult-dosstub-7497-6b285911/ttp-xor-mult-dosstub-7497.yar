rule TTP_XOR_MULT_DOSStub_7497 {
  strings:
    $key_7497 = { 20 ff [2] 54 e7 [2] 13 e5 [2] 54 f4 [2] 1a f8 [2] 16 f2 [2] 01 f9 [2] 1a b7 [2] 27 }

  condition:
    any of them
}