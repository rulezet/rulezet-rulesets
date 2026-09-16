rule TTP_XOR_MULT_DOSStub_5790 {
  strings:
    $key_5790 = { 03 f8 [2] 77 e0 [2] 30 e2 [2] 77 f3 [2] 39 ff [2] 35 f5 [2] 22 fe [2] 39 b0 [2] 04 }

  condition:
    any of them
}