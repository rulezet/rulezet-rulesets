rule TTP_XOR_MULT_DOSStub_369b {
  strings:
    $key_369b = { 62 f3 [2] 16 eb [2] 51 e9 [2] 16 f8 [2] 58 f4 [2] 54 fe [2] 43 f5 [2] 58 bb [2] 65 }

  condition:
    any of them
}