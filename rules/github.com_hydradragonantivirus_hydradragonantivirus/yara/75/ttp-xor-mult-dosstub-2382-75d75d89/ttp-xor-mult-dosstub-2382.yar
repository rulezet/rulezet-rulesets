rule TTP_XOR_MULT_DOSStub_2382 {
  strings:
    $key_2382 = { 77 ea [2] 03 f2 [2] 44 f0 [2] 03 e1 [2] 4d ed [2] 41 e7 [2] 56 ec [2] 4d a2 [2] 70 }

  condition:
    any of them
}