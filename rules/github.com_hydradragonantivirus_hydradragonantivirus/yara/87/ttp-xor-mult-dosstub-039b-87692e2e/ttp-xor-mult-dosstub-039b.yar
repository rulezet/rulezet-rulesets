rule TTP_XOR_MULT_DOSStub_039b {
  strings:
    $key_039b = { 57 f3 [2] 23 eb [2] 64 e9 [2] 23 f8 [2] 6d f4 [2] 61 fe [2] 76 f5 [2] 6d bb [2] 50 }

  condition:
    any of them
}