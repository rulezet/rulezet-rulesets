rule TTP_XOR_MULT_DOSStub_349b {
  strings:
    $key_349b = { 60 f3 [2] 14 eb [2] 53 e9 [2] 14 f8 [2] 5a f4 [2] 56 fe [2] 41 f5 [2] 5a bb [2] 67 }

  condition:
    any of them
}