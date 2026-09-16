rule TTP_XOR_MULT_DOSStub_4886 {
  strings:
    $key_4886 = { 1c ee [2] 68 f6 [2] 2f f4 [2] 68 e5 [2] 26 e9 [2] 2a e3 [2] 3d e8 [2] 26 a6 [2] 1b }

  condition:
    any of them
}