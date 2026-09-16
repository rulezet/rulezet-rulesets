rule TTP_XOR_MULT_DOSStub_f884 {
  strings:
    $key_f884 = { ac ec [2] d8 f4 [2] 9f f6 [2] d8 e7 [2] 96 eb [2] 9a e1 [2] 8d ea [2] 96 a4 [2] ab }

  condition:
    any of them
}