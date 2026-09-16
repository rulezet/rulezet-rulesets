rule TTP_XOR_MULT_DOSStub_d383 {
  strings:
    $key_d383 = { 87 eb [2] f3 f3 [2] b4 f1 [2] f3 e0 [2] bd ec [2] b1 e6 [2] a6 ed [2] bd a3 [2] 80 }

  condition:
    any of them
}