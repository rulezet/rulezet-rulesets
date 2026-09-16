rule TTP_XOR_MULT_DOSStub_3382 {
  strings:
    $key_3382 = { 67 ea [2] 13 f2 [2] 54 f0 [2] 13 e1 [2] 5d ed [2] 51 e7 [2] 46 ec [2] 5d a2 [2] 60 }

  condition:
    any of them
}