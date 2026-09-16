rule TTP_XOR_MULT_DOSStub_6691 {
  strings:
    $key_6691 = { 32 f9 [2] 46 e1 [2] 01 e3 [2] 46 f2 [2] 08 fe [2] 04 f4 [2] 13 ff [2] 08 b1 [2] 35 }

  condition:
    any of them
}