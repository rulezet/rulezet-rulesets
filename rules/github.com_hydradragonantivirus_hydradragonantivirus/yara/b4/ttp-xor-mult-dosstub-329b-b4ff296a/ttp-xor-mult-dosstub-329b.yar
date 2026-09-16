rule TTP_XOR_MULT_DOSStub_329b {
  strings:
    $key_329b = { 66 f3 [2] 12 eb [2] 55 e9 [2] 12 f8 [2] 5c f4 [2] 50 fe [2] 47 f5 [2] 5c bb [2] 61 }

  condition:
    any of them
}