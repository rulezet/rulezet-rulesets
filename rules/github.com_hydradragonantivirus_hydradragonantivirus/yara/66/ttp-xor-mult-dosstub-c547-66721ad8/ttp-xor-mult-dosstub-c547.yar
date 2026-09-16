rule TTP_XOR_MULT_DOSStub_c547 {
  strings:
    $key_c547 = { 91 2f [2] e5 37 [2] a2 35 [2] e5 24 [2] ab 28 [2] a7 22 [2] b0 29 [2] ab 67 [2] 96 }

  condition:
    any of them
}