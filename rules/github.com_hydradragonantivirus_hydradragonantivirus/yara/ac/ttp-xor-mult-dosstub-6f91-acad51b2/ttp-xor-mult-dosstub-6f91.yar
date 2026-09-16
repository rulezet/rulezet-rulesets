rule TTP_XOR_MULT_DOSStub_6f91 {
  strings:
    $key_6f91 = { 3b f9 [2] 4f e1 [2] 08 e3 [2] 4f f2 [2] 01 fe [2] 0d f4 [2] 1a ff [2] 01 b1 [2] 3c }

  condition:
    any of them
}