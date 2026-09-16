rule TTP_XOR_MULT_DOSStub_d684 {
  strings:
    $key_d684 = { 82 ec [2] f6 f4 [2] b1 f6 [2] f6 e7 [2] b8 eb [2] b4 e1 [2] a3 ea [2] b8 a4 [2] 85 }

  condition:
    any of them
}