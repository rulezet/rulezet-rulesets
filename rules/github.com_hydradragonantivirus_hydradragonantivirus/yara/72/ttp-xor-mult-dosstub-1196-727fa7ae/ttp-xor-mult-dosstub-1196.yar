rule TTP_XOR_MULT_DOSStub_1196 {
  strings:
    $key_1196 = { 45 fe [2] 31 e6 [2] 76 e4 [2] 31 f5 [2] 7f f9 [2] 73 f3 [2] 64 f8 [2] 7f b6 [2] 42 }

  condition:
    any of them
}