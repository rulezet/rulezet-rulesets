rule TTP_XOR_MULT_DOSStub_2b90 {
  strings:
    $key_2b90 = { 7f f8 [2] 0b e0 [2] 4c e2 [2] 0b f3 [2] 45 ff [2] 49 f5 [2] 5e fe [2] 45 b0 [2] 78 }

  condition:
    any of them
}