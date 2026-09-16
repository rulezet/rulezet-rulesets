rule TTP_XOR_MULT_DOSStub_0b90 {
  strings:
    $key_0b90 = { 5f f8 [2] 2b e0 [2] 6c e2 [2] 2b f3 [2] 65 ff [2] 69 f5 [2] 7e fe [2] 65 b0 [2] 58 }

  condition:
    any of them
}