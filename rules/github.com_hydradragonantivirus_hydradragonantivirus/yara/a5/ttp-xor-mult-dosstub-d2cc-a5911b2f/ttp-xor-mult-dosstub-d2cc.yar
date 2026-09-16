rule TTP_XOR_MULT_DOSStub_d2cc {
  strings:
    $key_d2cc = { 86 a4 [2] f2 bc [2] b5 be [2] f2 af [2] bc a3 [2] b0 a9 [2] a7 a2 [2] bc ec [2] 81 }

  condition:
    any of them
}