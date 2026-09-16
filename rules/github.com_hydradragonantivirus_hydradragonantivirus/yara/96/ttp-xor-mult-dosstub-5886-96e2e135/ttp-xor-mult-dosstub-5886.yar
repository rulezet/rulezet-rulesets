rule TTP_XOR_MULT_DOSStub_5886 {
  strings:
    $key_5886 = { 0c ee [2] 78 f6 [2] 3f f4 [2] 78 e5 [2] 36 e9 [2] 3a e3 [2] 2d e8 [2] 36 a6 [2] 0b }

  condition:
    any of them
}