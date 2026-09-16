rule TTP_XOR_MULT_DOSStub_6291 {
  strings:
    $key_6291 = { 36 f9 [2] 42 e1 [2] 05 e3 [2] 42 f2 [2] 0c fe [2] 00 f4 [2] 17 ff [2] 0c b1 [2] 31 }

  condition:
    any of them
}