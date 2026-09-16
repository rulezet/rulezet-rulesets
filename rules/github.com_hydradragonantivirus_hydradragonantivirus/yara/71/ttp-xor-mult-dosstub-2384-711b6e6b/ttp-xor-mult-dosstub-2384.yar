rule TTP_XOR_MULT_DOSStub_2384 {
  strings:
    $key_2384 = { 77 ec [2] 03 f4 [2] 44 f6 [2] 03 e7 [2] 4d eb [2] 41 e1 [2] 56 ea [2] 4d a4 [2] 70 }

  condition:
    any of them
}