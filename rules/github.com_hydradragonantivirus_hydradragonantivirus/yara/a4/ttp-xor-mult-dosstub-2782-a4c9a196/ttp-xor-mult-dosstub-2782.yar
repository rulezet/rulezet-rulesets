rule TTP_XOR_MULT_DOSStub_2782 {
  strings:
    $key_2782 = { 73 ea [2] 07 f2 [2] 40 f0 [2] 07 e1 [2] 49 ed [2] 45 e7 [2] 52 ec [2] 49 a2 [2] 74 }

  condition:
    any of them
}