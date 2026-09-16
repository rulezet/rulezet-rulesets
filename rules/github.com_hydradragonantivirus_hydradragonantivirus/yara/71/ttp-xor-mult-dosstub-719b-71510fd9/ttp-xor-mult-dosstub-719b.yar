rule TTP_XOR_MULT_DOSStub_719b {
  strings:
    $key_719b = { 25 f3 [2] 51 eb [2] 16 e9 [2] 51 f8 [2] 1f f4 [2] 13 fe [2] 04 f5 [2] 1f bb [2] 22 }

  condition:
    any of them
}