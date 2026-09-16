rule TTP_XOR_MULT_DOSStub_4d91 {
  strings:
    $key_4d91 = { 19 f9 [2] 6d e1 [2] 2a e3 [2] 6d f2 [2] 23 fe [2] 2f f4 [2] 38 ff [2] 23 b1 [2] 1e }

  condition:
    any of them
}