rule TTP_XOR_MULT_DOSStub_309b {
  strings:
    $key_309b = { 64 f3 [2] 10 eb [2] 57 e9 [2] 10 f8 [2] 5e f4 [2] 52 fe [2] 45 f5 [2] 5e bb [2] 63 }

  condition:
    any of them
}