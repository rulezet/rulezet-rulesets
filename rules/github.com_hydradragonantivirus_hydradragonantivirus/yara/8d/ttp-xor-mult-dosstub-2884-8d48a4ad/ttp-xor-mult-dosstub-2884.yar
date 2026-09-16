rule TTP_XOR_MULT_DOSStub_2884 {
  strings:
    $key_2884 = { 7c ec [2] 08 f4 [2] 4f f6 [2] 08 e7 [2] 46 eb [2] 4a e1 [2] 5d ea [2] 46 a4 [2] 7b }

  condition:
    any of them
}