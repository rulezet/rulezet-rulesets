rule TTP_XOR_MULT_DOSStub_6e91 {
  strings:
    $key_6e91 = { 3a f9 [2] 4e e1 [2] 09 e3 [2] 4e f2 [2] 00 fe [2] 0c f4 [2] 1b ff [2] 00 b1 [2] 3d }

  condition:
    any of them
}