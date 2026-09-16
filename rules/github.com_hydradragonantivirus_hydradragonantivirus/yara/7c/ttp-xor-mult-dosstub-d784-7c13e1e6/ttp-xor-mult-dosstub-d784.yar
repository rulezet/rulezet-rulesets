rule TTP_XOR_MULT_DOSStub_d784 {
  strings:
    $key_d784 = { 83 ec [2] f7 f4 [2] b0 f6 [2] f7 e7 [2] b9 eb [2] b5 e1 [2] a2 ea [2] b9 a4 [2] 84 }

  condition:
    any of them
}