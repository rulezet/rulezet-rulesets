rule TTP_XOR_MULT_DOSStub_4791 {
  strings:
    $key_4791 = { 13 f9 [2] 67 e1 [2] 20 e3 [2] 67 f2 [2] 29 fe [2] 25 f4 [2] 32 ff [2] 29 b1 [2] 14 }

  condition:
    any of them
}