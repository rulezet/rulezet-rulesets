rule TTP_XOR_MULT_DOSStub_6b90 {
  strings:
    $key_6b90 = { 3f f8 [2] 4b e0 [2] 0c e2 [2] 4b f3 [2] 05 ff [2] 09 f5 [2] 1e fe [2] 05 b0 [2] 38 }

  condition:
    any of them
}