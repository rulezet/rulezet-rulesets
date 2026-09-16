rule TTP_XOR_MULT_DOSStub_6690 {
  strings:
    $key_6690 = { 32 f8 [2] 46 e0 [2] 01 e2 [2] 46 f3 [2] 08 ff [2] 04 f5 [2] 13 fe [2] 08 b0 [2] 35 }

  condition:
    any of them
}