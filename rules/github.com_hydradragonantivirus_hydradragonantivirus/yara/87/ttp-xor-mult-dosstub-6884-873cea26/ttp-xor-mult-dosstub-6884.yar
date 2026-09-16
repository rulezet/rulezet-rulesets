rule TTP_XOR_MULT_DOSStub_6884 {
  strings:
    $key_6884 = { 3c ec [2] 48 f4 [2] 0f f6 [2] 48 e7 [2] 06 eb [2] 0a e1 [2] 1d ea [2] 06 a4 [2] 3b }

  condition:
    any of them
}