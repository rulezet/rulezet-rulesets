rule TTP_XOR_MULT_DOSStub_1582 {
  strings:
    $key_1582 = { 41 ea [2] 35 f2 [2] 72 f0 [2] 35 e1 [2] 7b ed [2] 77 e7 [2] 60 ec [2] 7b a2 [2] 46 }

  condition:
    any of them
}