rule TTP_XOR_MULT_DOSStub_c382 {
  strings:
    $key_c382 = { 97 ea [2] e3 f2 [2] a4 f0 [2] e3 e1 [2] ad ed [2] a1 e7 [2] b6 ec [2] ad a2 [2] 90 }

  condition:
    any of them
}