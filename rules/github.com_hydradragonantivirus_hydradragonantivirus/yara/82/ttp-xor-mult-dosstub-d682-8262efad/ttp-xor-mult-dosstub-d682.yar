rule TTP_XOR_MULT_DOSStub_d682 {
  strings:
    $key_d682 = { 82 ea [2] f6 f2 [2] b1 f0 [2] f6 e1 [2] b8 ed [2] b4 e7 [2] a3 ec [2] b8 a2 [2] 85 }

  condition:
    any of them
}