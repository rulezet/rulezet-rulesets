rule TTP_XOR_MULT_DOSStub_3f91 {
  strings:
    $key_3f91 = { 6b f9 [2] 1f e1 [2] 58 e3 [2] 1f f2 [2] 51 fe [2] 5d f4 [2] 4a ff [2] 51 b1 [2] 6c }

  condition:
    any of them
}