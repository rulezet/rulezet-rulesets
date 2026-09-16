rule TTP_XOR_MULT_DOSStub_3d91 {
  strings:
    $key_3d91 = { 69 f9 [2] 1d e1 [2] 5a e3 [2] 1d f2 [2] 53 fe [2] 5f f4 [2] 48 ff [2] 53 b1 [2] 6e }

  condition:
    any of them
}