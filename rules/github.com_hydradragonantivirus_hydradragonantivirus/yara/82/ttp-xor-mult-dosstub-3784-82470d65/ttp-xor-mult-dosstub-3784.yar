rule TTP_XOR_MULT_DOSStub_3784 {
  strings:
    $key_3784 = { 63 ec [2] 17 f4 [2] 50 f6 [2] 17 e7 [2] 59 eb [2] 55 e1 [2] 42 ea [2] 59 a4 [2] 64 }

  condition:
    any of them
}