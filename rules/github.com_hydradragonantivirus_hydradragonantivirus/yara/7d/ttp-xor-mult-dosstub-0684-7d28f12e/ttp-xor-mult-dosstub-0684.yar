rule TTP_XOR_MULT_DOSStub_0684 {
  strings:
    $key_0684 = { 52 ec [2] 26 f4 [2] 61 f6 [2] 26 e7 [2] 68 eb [2] 64 e1 [2] 73 ea [2] 68 a4 [2] 55 }

  condition:
    any of them
}