rule TTP_XOR_MULT_DOSStub_2784 {
  strings:
    $key_2784 = { 73 ec [2] 07 f4 [2] 40 f6 [2] 07 e7 [2] 49 eb [2] 45 e1 [2] 52 ea [2] 49 a4 [2] 74 }

  condition:
    any of them
}