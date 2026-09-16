rule TTP_XOR_MULT_DOSStub_6d91 {
  strings:
    $key_6d91 = { 39 f9 [2] 4d e1 [2] 0a e3 [2] 4d f2 [2] 03 fe [2] 0f f4 [2] 18 ff [2] 03 b1 [2] 3e }

  condition:
    any of them
}