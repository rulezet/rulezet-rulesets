rule TTP_XOR_MULT_DOSStub_339b {
  strings:
    $key_339b = { 67 f3 [2] 13 eb [2] 54 e9 [2] 13 f8 [2] 5d f4 [2] 51 fe [2] 46 f5 [2] 5d bb [2] 60 }

  condition:
    any of them
}