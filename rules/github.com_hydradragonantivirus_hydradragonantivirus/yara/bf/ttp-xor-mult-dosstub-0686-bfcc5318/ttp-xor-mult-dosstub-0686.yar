rule TTP_XOR_MULT_DOSStub_0686 {
  strings:
    $key_0686 = { 52 ee [2] 26 f6 [2] 61 f4 [2] 26 e5 [2] 68 e9 [2] 64 e3 [2] 73 e8 [2] 68 a6 [2] 55 }

  condition:
    any of them
}