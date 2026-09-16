rule TTP_XOR_MULT_DOSStub_2682 {
  strings:
    $key_2682 = { 72 ea [2] 06 f2 [2] 41 f0 [2] 06 e1 [2] 48 ed [2] 44 e7 [2] 53 ec [2] 48 a2 [2] 75 }

  condition:
    any of them
}