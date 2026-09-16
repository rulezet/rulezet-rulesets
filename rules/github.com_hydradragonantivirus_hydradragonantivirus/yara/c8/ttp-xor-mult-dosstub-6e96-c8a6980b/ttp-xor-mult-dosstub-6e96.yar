rule TTP_XOR_MULT_DOSStub_6e96 {
  strings:
    $key_6e96 = { 3a fe [2] 4e e6 [2] 09 e4 [2] 4e f5 [2] 00 f9 [2] 0c f3 [2] 1b f8 [2] 00 b6 [2] 3d }

  condition:
    any of them
}