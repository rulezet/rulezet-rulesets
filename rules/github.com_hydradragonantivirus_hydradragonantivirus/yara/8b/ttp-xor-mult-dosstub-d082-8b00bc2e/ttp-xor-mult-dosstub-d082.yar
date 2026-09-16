rule TTP_XOR_MULT_DOSStub_d082 {
  strings:
    $key_d082 = { 84 ea [2] f0 f2 [2] b7 f0 [2] f0 e1 [2] be ed [2] b2 e7 [2] a5 ec [2] be a2 [2] 83 }

  condition:
    any of them
}