rule TTP_XOR_MULT_DOSStub_f882 {
  strings:
    $key_f882 = { ac ea [2] d8 f2 [2] 9f f0 [2] d8 e1 [2] 96 ed [2] 9a e7 [2] 8d ec [2] 96 a2 [2] ab }

  condition:
    any of them
}