rule TTP_XOR_MULT_DOSStub_c5cc {
  strings:
    $key_c5cc = { 91 a4 [2] e5 bc [2] a2 be [2] e5 af [2] ab a3 [2] a7 a9 [2] b0 a2 [2] ab ec [2] 96 }

  condition:
    any of them
}