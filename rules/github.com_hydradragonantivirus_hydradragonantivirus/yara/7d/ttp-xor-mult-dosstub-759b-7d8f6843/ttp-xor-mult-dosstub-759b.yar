rule TTP_XOR_MULT_DOSStub_759b {
  strings:
    $key_759b = { 21 f3 [2] 55 eb [2] 12 e9 [2] 55 f8 [2] 1b f4 [2] 17 fe [2] 00 f5 [2] 1b bb [2] 26 }

  condition:
    any of them
}