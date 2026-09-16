rule TTP_XOR_MULT_DOSStub_5b90 {
  strings:
    $key_5b90 = { 0f f8 [2] 7b e0 [2] 3c e2 [2] 7b f3 [2] 35 ff [2] 39 f5 [2] 2e fe [2] 35 b0 [2] 08 }

  condition:
    any of them
}