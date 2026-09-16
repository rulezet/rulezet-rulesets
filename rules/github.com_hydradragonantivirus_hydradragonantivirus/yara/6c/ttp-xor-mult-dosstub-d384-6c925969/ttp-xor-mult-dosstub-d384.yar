rule TTP_XOR_MULT_DOSStub_d384 {
  strings:
    $key_d384 = { 87 ec [2] f3 f4 [2] b4 f6 [2] f3 e7 [2] bd eb [2] b1 e1 [2] a6 ea [2] bd a4 [2] 80 }

  condition:
    any of them
}