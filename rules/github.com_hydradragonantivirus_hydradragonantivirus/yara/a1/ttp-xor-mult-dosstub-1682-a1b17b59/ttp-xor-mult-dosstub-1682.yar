rule TTP_XOR_MULT_DOSStub_1682 {
  strings:
    $key_1682 = { 42 ea [2] 36 f2 [2] 71 f0 [2] 36 e1 [2] 78 ed [2] 74 e7 [2] 63 ec [2] 78 a2 [2] 45 }

  condition:
    any of them
}