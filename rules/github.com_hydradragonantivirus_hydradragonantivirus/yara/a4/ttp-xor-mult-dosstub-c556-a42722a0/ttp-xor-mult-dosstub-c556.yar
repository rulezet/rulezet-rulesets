rule TTP_XOR_MULT_DOSStub_c556 {
  strings:
    $key_c556 = { 91 3e [2] e5 26 [2] a2 24 [2] e5 35 [2] ab 39 [2] a7 33 [2] b0 38 [2] ab 76 [2] 96 }

  condition:
    any of them
}