rule TTP_XOR_MULT_DOSStub_c5e0 {
  strings:
    $key_c5e0 = { 91 88 [2] e5 90 [2] a2 92 [2] e5 83 [2] ab 8f [2] a7 85 [2] b0 8e [2] ab c0 [2] 96 }

  condition:
    any of them
}