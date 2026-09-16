rule TTP_XOR_MULT_DOSStub_7d90 {
  strings:
    $key_7d90 = { 29 f8 [2] 5d e0 [2] 1a e2 [2] 5d f3 [2] 13 ff [2] 1f f5 [2] 08 fe [2] 13 b0 [2] 2e }

  condition:
    any of them
}