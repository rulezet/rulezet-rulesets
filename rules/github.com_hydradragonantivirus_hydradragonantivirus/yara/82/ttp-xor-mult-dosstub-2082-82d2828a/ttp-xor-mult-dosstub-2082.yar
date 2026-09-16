rule TTP_XOR_MULT_DOSStub_2082 {
  strings:
    $key_2082 = { 74 ea [2] 00 f2 [2] 47 f0 [2] 00 e1 [2] 4e ed [2] 42 e7 [2] 55 ec [2] 4e a2 [2] 73 }

  condition:
    any of them
}