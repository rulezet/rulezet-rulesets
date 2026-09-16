rule TTP_XOR_MULT_DOSStub_6682 {
  strings:
    $key_6682 = { 32 ea [2] 46 f2 [2] 01 f0 [2] 46 e1 [2] 08 ed [2] 04 e7 [2] 13 ec [2] 08 a2 [2] 35 }

  condition:
    any of them
}