rule TTP_XOR_MULT_DOSStub_3b96 {
  strings:
    $key_3b96 = { 6f fe [2] 1b e6 [2] 5c e4 [2] 1b f5 [2] 55 f9 [2] 59 f3 [2] 4e f8 [2] 55 b6 [2] 68 }

  condition:
    any of them
}