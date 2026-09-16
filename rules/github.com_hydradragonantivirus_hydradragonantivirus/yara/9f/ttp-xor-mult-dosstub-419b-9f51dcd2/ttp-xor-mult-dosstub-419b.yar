rule TTP_XOR_MULT_DOSStub_419b {
  strings:
    $key_419b = { 15 f3 [2] 61 eb [2] 26 e9 [2] 61 f8 [2] 2f f4 [2] 23 fe [2] 34 f5 [2] 2f bb [2] 12 }

  condition:
    any of them
}