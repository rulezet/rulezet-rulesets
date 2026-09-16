rule TTP_XOR_MULT_DOSStub_c501 {
  strings:
    $key_c501 = { 91 69 [2] e5 71 [2] a2 73 [2] e5 62 [2] ab 6e [2] a7 64 [2] b0 6f [2] ab 21 [2] 96 }

  condition:
    any of them
}