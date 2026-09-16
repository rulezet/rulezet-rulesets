rule TTP_XOR_MULT_DOSStub_7d91 {
  strings:
    $key_7d91 = { 29 f9 [2] 5d e1 [2] 1a e3 [2] 5d f2 [2] 13 fe [2] 1f f4 [2] 08 ff [2] 13 b1 [2] 2e }

  condition:
    any of them
}