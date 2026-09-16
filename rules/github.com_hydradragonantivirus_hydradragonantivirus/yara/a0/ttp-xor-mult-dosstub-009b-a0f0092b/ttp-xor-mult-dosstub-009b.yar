rule TTP_XOR_MULT_DOSStub_009b {
  strings:
    $key_009b = { 54 f3 [2] 20 eb [2] 67 e9 [2] 20 f8 [2] 6e f4 [2] 62 fe [2] 75 f5 [2] 6e bb [2] 53 }

  condition:
    any of them
}