rule TTP_XOR_MULT_DOSStub_4b90 {
  strings:
    $key_4b90 = { 1f f8 [2] 6b e0 [2] 2c e2 [2] 6b f3 [2] 25 ff [2] 29 f5 [2] 3e fe [2] 25 b0 [2] 18 }

  condition:
    any of them
}