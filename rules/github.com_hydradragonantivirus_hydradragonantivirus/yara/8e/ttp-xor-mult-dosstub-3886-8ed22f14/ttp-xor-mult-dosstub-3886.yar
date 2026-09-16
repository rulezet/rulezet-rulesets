rule TTP_XOR_MULT_DOSStub_3886 {
  strings:
    $key_3886 = { 6c ee [2] 18 f6 [2] 5f f4 [2] 18 e5 [2] 56 e9 [2] 5a e3 [2] 4d e8 [2] 56 a6 [2] 6b }

  condition:
    any of them
}