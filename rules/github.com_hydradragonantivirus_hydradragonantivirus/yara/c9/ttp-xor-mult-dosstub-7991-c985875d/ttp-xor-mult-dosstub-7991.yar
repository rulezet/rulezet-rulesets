rule TTP_XOR_MULT_DOSStub_7991 {
  strings:
    $key_7991 = { 2d f9 [2] 59 e1 [2] 1e e3 [2] 59 f2 [2] 17 fe [2] 1b f4 [2] 0c ff [2] 17 b1 [2] 2a }

  condition:
    any of them
}