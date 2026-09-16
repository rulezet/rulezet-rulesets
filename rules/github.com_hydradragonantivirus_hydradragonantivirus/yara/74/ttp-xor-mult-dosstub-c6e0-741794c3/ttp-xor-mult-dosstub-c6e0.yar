rule TTP_XOR_MULT_DOSStub_c6e0 {
  strings:
    $key_c6e0 = { 92 88 [2] e6 90 [2] a1 92 [2] e6 83 [2] a8 8f [2] a4 85 [2] b3 8e [2] a8 c0 [2] 95 }

  condition:
    any of them
}