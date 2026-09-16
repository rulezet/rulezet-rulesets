rule TTP_XOR_MULT_DOSStub_0690 {
  strings:
    $key_0690 = { 52 f8 [2] 26 e0 [2] 61 e2 [2] 26 f3 [2] 68 ff [2] 64 f5 [2] 73 fe [2] 68 b0 [2] 55 }

  condition:
    any of them
}