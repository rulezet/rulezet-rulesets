rule TTP_XOR_MULT_DOSStub_709b {
  strings:
    $key_709b = { 24 f3 [2] 50 eb [2] 17 e9 [2] 50 f8 [2] 1e f4 [2] 12 fe [2] 05 f5 [2] 1e bb [2] 23 }

  condition:
    any of them
}