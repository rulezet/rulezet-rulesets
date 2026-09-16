rule TTP_XOR_MULT_DOSStub_359b {
  strings:
    $key_359b = { 61 f3 [2] 15 eb [2] 52 e9 [2] 15 f8 [2] 5b f4 [2] 57 fe [2] 40 f5 [2] 5b bb [2] 66 }

  condition:
    any of them
}