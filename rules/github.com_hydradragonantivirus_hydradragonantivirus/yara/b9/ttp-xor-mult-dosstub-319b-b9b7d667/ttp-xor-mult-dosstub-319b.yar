rule TTP_XOR_MULT_DOSStub_319b {
  strings:
    $key_319b = { 65 f3 [2] 11 eb [2] 56 e9 [2] 11 f8 [2] 5f f4 [2] 53 fe [2] 44 f5 [2] 5f bb [2] 62 }

  condition:
    any of them
}