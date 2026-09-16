rule TTP_XOR_MULT_DOSStub_509b {
  strings:
    $key_509b = { 04 f3 [2] 70 eb [2] 37 e9 [2] 70 f8 [2] 3e f4 [2] 32 fe [2] 25 f5 [2] 3e bb [2] 03 }

  condition:
    any of them
}