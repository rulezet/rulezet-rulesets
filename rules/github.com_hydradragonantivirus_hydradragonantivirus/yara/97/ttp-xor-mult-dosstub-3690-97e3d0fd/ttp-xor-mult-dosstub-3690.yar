rule TTP_XOR_MULT_DOSStub_3690 {
  strings:
    $key_3690 = { 62 f8 [2] 16 e0 [2] 51 e2 [2] 16 f3 [2] 58 ff [2] 54 f5 [2] 43 fe [2] 58 b0 [2] 65 }

  condition:
    any of them
}