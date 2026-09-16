rule TTP_XOR_MULT_DOSStub_c531 {
  strings:
    $key_c531 = { 91 59 [2] e5 41 [2] a2 43 [2] e5 52 [2] ab 5e [2] a7 54 [2] b0 5f [2] ab 11 [2] 96 }

  condition:
    any of them
}