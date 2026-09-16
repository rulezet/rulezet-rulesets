rule TTP_XOR_MULT_DOSStub_7b96 {
  strings:
    $key_7b96 = { 2f fe [2] 5b e6 [2] 1c e4 [2] 5b f5 [2] 15 f9 [2] 19 f3 [2] 0e f8 [2] 15 b6 [2] 28 }

  condition:
    any of them
}