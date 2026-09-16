rule TTP_XOR_MULT_DOSStub_1791 {
  strings:
    $key_1791 = { 43 f9 [2] 37 e1 [2] 70 e3 [2] 37 f2 [2] 79 fe [2] 75 f4 [2] 62 ff [2] 79 b1 [2] 44 }

  condition:
    any of them
}