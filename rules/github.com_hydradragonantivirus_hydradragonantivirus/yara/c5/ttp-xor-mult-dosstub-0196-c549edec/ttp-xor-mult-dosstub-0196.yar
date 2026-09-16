rule TTP_XOR_MULT_DOSStub_0196 {
  strings:
    $key_0196 = { 55 fe [2] 21 e6 [2] 66 e4 [2] 21 f5 [2] 6f f9 [2] 63 f3 [2] 74 f8 [2] 6f b6 [2] 52 }

  condition:
    any of them
}