rule TTP_XOR_MULT_DOSStub_449b {
  strings:
    $key_449b = { 10 f3 [2] 64 eb [2] 23 e9 [2] 64 f8 [2] 2a f4 [2] 26 fe [2] 31 f5 [2] 2a bb [2] 17 }

  condition:
    any of them
}