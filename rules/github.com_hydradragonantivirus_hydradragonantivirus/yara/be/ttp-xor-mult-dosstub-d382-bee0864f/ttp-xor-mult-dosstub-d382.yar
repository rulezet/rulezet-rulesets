rule TTP_XOR_MULT_DOSStub_d382 {
  strings:
    $key_d382 = { 87 ea [2] f3 f2 [2] b4 f0 [2] f3 e1 [2] bd ed [2] b1 e7 [2] a6 ec [2] bd a2 [2] 80 }

  condition:
    any of them
}