rule TTP_XOR_MULT_DOSStub_3582 {
  strings:
    $key_3582 = { 61 ea [2] 15 f2 [2] 52 f0 [2] 15 e1 [2] 5b ed [2] 57 e7 [2] 40 ec [2] 5b a2 [2] 66 }

  condition:
    any of them
}