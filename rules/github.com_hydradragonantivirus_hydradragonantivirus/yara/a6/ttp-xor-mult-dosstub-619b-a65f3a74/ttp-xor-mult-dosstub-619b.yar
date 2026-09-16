rule TTP_XOR_MULT_DOSStub_619b {
  strings:
    $key_619b = { 35 f3 [2] 41 eb [2] 06 e9 [2] 41 f8 [2] 0f f4 [2] 03 fe [2] 14 f5 [2] 0f bb [2] 32 }

  condition:
    any of them
}