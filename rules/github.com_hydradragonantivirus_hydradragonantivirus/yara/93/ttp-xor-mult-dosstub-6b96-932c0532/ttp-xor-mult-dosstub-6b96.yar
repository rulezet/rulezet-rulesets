rule TTP_XOR_MULT_DOSStub_6b96 {
  strings:
    $key_6b96 = { 3f fe [2] 4b e6 [2] 0c e4 [2] 4b f5 [2] 05 f9 [2] 09 f3 [2] 1e f8 [2] 05 b6 [2] 38 }

  condition:
    any of them
}