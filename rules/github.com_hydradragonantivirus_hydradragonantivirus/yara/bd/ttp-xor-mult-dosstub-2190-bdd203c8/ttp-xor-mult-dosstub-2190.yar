rule TTP_XOR_MULT_DOSStub_2190 {
  strings:
    $key_2190 = { 75 f8 [2] 01 e0 [2] 46 e2 [2] 01 f3 [2] 4f ff [2] 43 f5 [2] 54 fe [2] 4f b0 [2] 72 }

  condition:
    any of them
}