rule TTP_XOR_MULT_DOSStub_2a90 {
  strings:
    $key_2a90 = { 7e f8 [2] 0a e0 [2] 4d e2 [2] 0a f3 [2] 44 ff [2] 48 f5 [2] 5f fe [2] 44 b0 [2] 79 }

  condition:
    any of them
}