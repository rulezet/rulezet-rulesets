rule TTP_XOR_MULT_DOSStub_c5e6 {
  strings:
    $key_c5e6 = { 91 8e [2] e5 96 [2] a2 94 [2] e5 85 [2] ab 89 [2] a7 83 [2] b0 88 [2] ab c6 [2] 96 }

  condition:
    any of them
}