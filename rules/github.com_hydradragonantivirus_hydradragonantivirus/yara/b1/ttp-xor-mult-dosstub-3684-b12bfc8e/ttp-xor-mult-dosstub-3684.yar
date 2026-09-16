rule TTP_XOR_MULT_DOSStub_3684 {
  strings:
    $key_3684 = { 62 ec [2] 16 f4 [2] 51 f6 [2] 16 e7 [2] 58 eb [2] 54 e1 [2] 43 ea [2] 58 a4 [2] 65 }

  condition:
    any of them
}