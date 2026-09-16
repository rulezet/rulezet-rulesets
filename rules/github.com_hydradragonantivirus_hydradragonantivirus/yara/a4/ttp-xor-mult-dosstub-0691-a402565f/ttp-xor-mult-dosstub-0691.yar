rule TTP_XOR_MULT_DOSStub_0691 {
  strings:
    $key_0691 = { 52 f9 [2] 26 e1 [2] 61 e3 [2] 26 f2 [2] 68 fe [2] 64 f4 [2] 73 ff [2] 68 b1 [2] 55 }

  condition:
    any of them
}