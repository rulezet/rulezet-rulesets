rule TTP_XOR_MULT_DOSStub_d482 {
  strings:
    $key_d482 = { 80 ea [2] f4 f2 [2] b3 f0 [2] f4 e1 [2] ba ed [2] b6 e7 [2] a1 ec [2] ba a2 [2] 87 }

  condition:
    any of them
}