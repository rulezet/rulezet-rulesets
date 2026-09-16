rule TTP_XOR_MULT_DOSStub_3d90 {
  strings:
    $key_3d90 = { 69 f8 [2] 1d e0 [2] 5a e2 [2] 1d f3 [2] 53 ff [2] 5f f5 [2] 48 fe [2] 53 b0 [2] 6e }

  condition:
    any of them
}