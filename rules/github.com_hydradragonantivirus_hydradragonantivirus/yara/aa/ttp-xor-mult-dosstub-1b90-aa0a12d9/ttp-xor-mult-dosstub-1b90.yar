rule TTP_XOR_MULT_DOSStub_1b90 {
  strings:
    $key_1b90 = { 4f f8 [2] 3b e0 [2] 7c e2 [2] 3b f3 [2] 75 ff [2] 79 f5 [2] 6e fe [2] 75 b0 [2] 48 }

  condition:
    any of them
}