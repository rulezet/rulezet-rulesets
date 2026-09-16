rule TTP_XOR_MULT_DOSStub_c506 {
  strings:
    $key_c506 = { 91 6e [2] e5 76 [2] a2 74 [2] e5 65 [2] ab 69 [2] a7 63 [2] b0 68 [2] ab 26 [2] 96 }

  condition:
    any of them
}