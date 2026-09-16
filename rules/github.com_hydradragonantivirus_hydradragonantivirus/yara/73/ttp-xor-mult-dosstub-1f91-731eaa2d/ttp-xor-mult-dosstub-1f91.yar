rule TTP_XOR_MULT_DOSStub_1f91 {
  strings:
    $key_1f91 = { 4b f9 [2] 3f e1 [2] 78 e3 [2] 3f f2 [2] 71 fe [2] 7d f4 [2] 6a ff [2] 71 b1 [2] 4c }

  condition:
    any of them
}