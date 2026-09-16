rule TTP_XOR_MULT_DOSStub_629b {
  strings:
    $key_629b = { 36 f3 [2] 42 eb [2] 05 e9 [2] 42 f8 [2] 0c f4 [2] 00 fe [2] 17 f5 [2] 0c bb [2] 31 }

  condition:
    any of them
}