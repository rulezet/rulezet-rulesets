rule TTP_XOR_MULT_DOSStub_149b {
  strings:
    $key_149b = { 40 f3 [2] 34 eb [2] 73 e9 [2] 34 f8 [2] 7a f4 [2] 76 fe [2] 61 f5 [2] 7a bb [2] 47 }

  condition:
    any of them
}