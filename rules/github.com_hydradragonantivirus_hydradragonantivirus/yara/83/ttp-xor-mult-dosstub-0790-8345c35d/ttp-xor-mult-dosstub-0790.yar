rule TTP_XOR_MULT_DOSStub_0790 {
  strings:
    $key_0790 = { 53 f8 [2] 27 e0 [2] 60 e2 [2] 27 f3 [2] 69 ff [2] 65 f5 [2] 72 fe [2] 69 b0 [2] 54 }

  condition:
    any of them
}