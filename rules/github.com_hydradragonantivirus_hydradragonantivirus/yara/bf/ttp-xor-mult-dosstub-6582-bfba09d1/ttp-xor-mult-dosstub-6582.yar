rule TTP_XOR_MULT_DOSStub_6582 {
  strings:
    $key_6582 = { 31 ea [2] 45 f2 [2] 02 f0 [2] 45 e1 [2] 0b ed [2] 07 e7 [2] 10 ec [2] 0b a2 [2] 36 }

  condition:
    any of them
}