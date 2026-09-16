rule TTP_XOR_MULT_DOSStub_c546 {
  strings:
    $key_c546 = { 91 2e [2] e5 36 [2] a2 34 [2] e5 25 [2] ab 29 [2] a7 23 [2] b0 28 [2] ab 66 [2] 96 }

  condition:
    any of them
}