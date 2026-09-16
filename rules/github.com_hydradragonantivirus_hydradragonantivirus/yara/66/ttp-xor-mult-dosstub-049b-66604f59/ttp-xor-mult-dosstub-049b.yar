rule TTP_XOR_MULT_DOSStub_049b {
  strings:
    $key_049b = { 50 f3 [2] 24 eb [2] 63 e9 [2] 24 f8 [2] 6a f4 [2] 66 fe [2] 71 f5 [2] 6a bb [2] 57 }

  condition:
    any of them
}