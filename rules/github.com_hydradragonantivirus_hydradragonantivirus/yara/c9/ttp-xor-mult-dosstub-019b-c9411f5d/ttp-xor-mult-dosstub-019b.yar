rule TTP_XOR_MULT_DOSStub_019b {
  strings:
    $key_019b = { 55 f3 [2] 21 eb [2] 66 e9 [2] 21 f8 [2] 6f f4 [2] 63 fe [2] 74 f5 [2] 6f bb [2] 52 }

  condition:
    any of them
}