rule TTP_XOR_MULT_DOSStub_2b96 {
  strings:
    $key_2b96 = { 7f fe [2] 0b e6 [2] 4c e4 [2] 0b f5 [2] 45 f9 [2] 49 f3 [2] 5e f8 [2] 45 b6 [2] 78 }

  condition:
    any of them
}