rule TTP_XOR_MULT_DOSStub_559b {
  strings:
    $key_559b = { 01 f3 [2] 75 eb [2] 32 e9 [2] 75 f8 [2] 3b f4 [2] 37 fe [2] 20 f5 [2] 3b bb [2] 06 }

  condition:
    any of them
}