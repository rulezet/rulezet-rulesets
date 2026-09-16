rule TTP_XOR_MULT_DOSStub_1d91 {
  strings:
    $key_1d91 = { 49 f9 [2] 3d e1 [2] 7a e3 [2] 3d f2 [2] 73 fe [2] 7f f4 [2] 68 ff [2] 73 b1 [2] 4e }

  condition:
    any of them
}