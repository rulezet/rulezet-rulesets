rule TTP_XOR_MULT_DOSStub_529b {
  strings:
    $key_529b = { 06 f3 [2] 72 eb [2] 35 e9 [2] 72 f8 [2] 3c f4 [2] 30 fe [2] 27 f5 [2] 3c bb [2] 01 }

  condition:
    any of them
}