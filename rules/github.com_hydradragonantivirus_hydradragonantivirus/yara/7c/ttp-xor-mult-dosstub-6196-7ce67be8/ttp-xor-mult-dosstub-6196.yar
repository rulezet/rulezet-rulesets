rule TTP_XOR_MULT_DOSStub_6196 {
  strings:
    $key_6196 = { 35 fe [2] 41 e6 [2] 06 e4 [2] 41 f5 [2] 0f f9 [2] 03 f3 [2] 14 f8 [2] 0f b6 [2] 32 }

  condition:
    any of them
}